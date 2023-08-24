'use strict';

var events = require('events');
var universalFetch = require('@inrupt/universal-fetch');
var jose = require('jose');
var uuid = require('uuid');

const SOLID_CLIENT_AUTHN_KEY_PREFIX = "solidClientAuthn:";
const PREFERRED_SIGNING_ALG = ["ES256", "RS256"];
const EVENTS = {
    ERROR: "error",
    LOGIN: "login",
    LOGOUT: "logout",
    NEW_REFRESH_TOKEN: "newRefreshToken",
    SESSION_EXPIRED: "sessionExpired",
    SESSION_EXTENDED: "sessionExtended",
    SESSION_RESTORED: "sessionRestore",
    TIMEOUT_SET: "timeoutSet",
};
const REFRESH_BEFORE_EXPIRATION_SECONDS = 5;
const SCOPE_OPENID = "openid";
const SCOPE_OFFLINE = "offline_access";
const SCOPE_WEBID = "webid";
const DEFAULT_SCOPES = [SCOPE_OPENID, SCOPE_OFFLINE, SCOPE_WEBID].join(" ");

const buildProxyHandler = (toExclude, errorMessage) => ({
    get(target, prop, receiver) {
        if (!Object.getOwnPropertyNames(events.EventEmitter).includes(prop) &&
            Object.getOwnPropertyNames(toExclude).includes(prop)) {
            throw new Error(`${errorMessage}: [${prop}] is not supported`);
        }
        return Reflect.get(target, prop, receiver);
    },
});

class AggregateHandler {
    constructor(handleables) {
        this.handleables = handleables;
    }
    async getProperHandler(params) {
        const canHandleList = await Promise.all(this.handleables.map((handleable) => handleable.canHandle(...params)));
        for (let i = 0; i < canHandleList.length; i += 1) {
            if (canHandleList[i]) {
                return this.handleables[i];
            }
        }
        return null;
    }
    async canHandle(...params) {
        return (await this.getProperHandler(params)) !== null;
    }
    async handle(...params) {
        const handler = await this.getProperHandler(params);
        if (handler) {
            return handler.handle(...params);
        }
        throw new Error(`[${this.constructor.name}] cannot find a suitable handler for: ${params
            .map((param) => {
            try {
                return JSON.stringify(param);
            }
            catch (err) {
                return param.toString();
            }
        })
            .join(", ")}`);
    }
}

async function fetchJwks(jwksIri, issuerIri) {
    const jwksResponse = await universalFetch.fetch.call(globalThis, jwksIri);
    if (jwksResponse.status !== 200) {
        throw new Error(`Could not fetch JWKS for [${issuerIri}] at [${jwksIri}]: ${jwksResponse.status} ${jwksResponse.statusText}`);
    }
    let jwk;
    try {
        jwk = (await jwksResponse.json()).keys[0];
    }
    catch (e) {
        throw new Error(`Malformed JWKS for [${issuerIri}] at [${jwksIri}]: ${e.message}`);
    }
    return jwk;
}
async function getWebidFromTokenPayload(idToken, jwksIri, issuerIri, clientId) {
    const jwk = await fetchJwks(jwksIri, issuerIri);
    let payload;
    try {
        const { payload: verifiedPayload } = await jose.jwtVerify(idToken, await jose.importJWK(jwk), {
            issuer: issuerIri,
            audience: clientId,
        });
        payload = verifiedPayload;
    }
    catch (e) {
        throw new Error(`Token verification failed: ${e.stack}`);
    }
    if (typeof payload.webid === "string") {
        return payload.webid;
    }
    if (typeof payload.sub !== "string") {
        throw new Error(`The token ${JSON.stringify(payload)} is invalid: it has no 'webid' claim and no 'sub' claim.`);
    }
    try {
        new URL(payload.sub);
        return payload.sub;
    }
    catch (e) {
        throw new Error(`The token has no 'webid' claim, and its 'sub' claim of [${payload.sub}] is invalid as a URL - error [${e}].`);
    }
}

function isValidRedirectUrl(redirectUrl) {
    try {
        const urlObject = new URL(redirectUrl);
        return urlObject.hash === "";
    }
    catch (e) {
        return false;
    }
}

class AuthorizationCodeWithPkceOidcHandlerBase {
    constructor(storageUtility, redirector) {
        this.storageUtility = storageUtility;
        this.redirector = redirector;
    }
    async canHandle(oidcLoginOptions) {
        return !!(oidcLoginOptions.issuerConfiguration.grantTypesSupported &&
            oidcLoginOptions.issuerConfiguration.grantTypesSupported.indexOf("authorization_code") > -1);
    }
    async handleRedirect({ oidcLoginOptions, state, codeVerifier, targetUrl, }) {
        await Promise.all([
            this.storageUtility.setForUser(state, {
                sessionId: oidcLoginOptions.sessionId,
            }),
            this.storageUtility.setForUser(oidcLoginOptions.sessionId, {
                codeVerifier,
                issuer: oidcLoginOptions.issuer.toString(),
                redirectUrl: oidcLoginOptions.redirectUrl,
                dpop: oidcLoginOptions.dpop ? "true" : "false",
            }),
        ]);
        this.redirector.redirect(targetUrl, {
            handleRedirect: oidcLoginOptions.handleRedirect,
        });
        return undefined;
    }
}

class GeneralLogoutHandler {
    constructor(sessionInfoManager) {
        this.sessionInfoManager = sessionInfoManager;
    }
    async canHandle() {
        return true;
    }
    async handle(userId) {
        await this.sessionInfoManager.clear(userId);
    }
}

class IRpLogoutHandler {
    constructor(redirector) {
        this.redirector = redirector;
    }
    async canHandle(userId, options) {
        return (options === null || options === void 0 ? void 0 : options.logoutType) === "idp";
    }
    async handle(userId, options) {
        if ((options === null || options === void 0 ? void 0 : options.logoutType) !== "idp") {
            throw new Error("Attempting to call idp logout handler to perform app logout");
        }
        if (options.toLogoutUrl === undefined) {
            throw new Error("Cannot perform IDP logout. Did you log in using the OIDC authentication flow?");
        }
        this.redirector.redirect(options.toLogoutUrl(options), {
            handleRedirect: options.handleRedirect,
        });
    }
}

class IWaterfallLogoutHandler {
    constructor(sessionInfoManager, redirector) {
        this.handlers = [
            new GeneralLogoutHandler(sessionInfoManager),
            new IRpLogoutHandler(redirector),
        ];
    }
    async canHandle() {
        return true;
    }
    async handle(userId, options) {
        for (const handler of this.handlers) {
            if (await handler.canHandle(userId, options))
                await handler.handle(userId, options);
        }
    }
}

function getUnauthenticatedSession() {
    return {
        isLoggedIn: false,
        sessionId: uuid.v4(),
        fetch: (...args) => universalFetch.fetch.call(globalThis, ...args),
    };
}
async function clear(sessionId, storage) {
    await Promise.all([
        storage.deleteAllUserData(sessionId, { secure: false }),
        storage.deleteAllUserData(sessionId, { secure: true }),
    ]);
}
class SessionInfoManagerBase {
    constructor(storageUtility) {
        this.storageUtility = storageUtility;
    }
    update(_sessionId, _options) {
        throw new Error("Not Implemented");
    }
    get(_) {
        throw new Error("Not implemented");
    }
    async getAll() {
        throw new Error("Not implemented");
    }
    async clear(sessionId) {
        return clear(sessionId, this.storageUtility);
    }
    async register(_sessionId) {
        throw new Error("Not implemented");
    }
    async getRegisteredSessionIdAll() {
        throw new Error("Not implemented");
    }
    async clearAll() {
        throw new Error("Not implemented");
    }
}

function getEndSessionUrl({ endSessionEndpoint, idTokenHint, postLogoutRedirectUri, state, }) {
    const url = new URL(endSessionEndpoint);
    if (idTokenHint !== undefined)
        url.searchParams.append("id_token_hint", idTokenHint);
    if (postLogoutRedirectUri !== undefined) {
        url.searchParams.append("post_logout_redirect_uri", postLogoutRedirectUri);
        if (state !== undefined)
            url.searchParams.append("state", state);
    }
    return url.toString();
}
function maybeBuildRpInitiatedLogout({ endSessionEndpoint, idTokenHint, }) {
    if (endSessionEndpoint === undefined)
        return undefined;
    return function logout({ state, postLogoutUrl }) {
        return getEndSessionUrl({
            endSessionEndpoint,
            idTokenHint,
            state,
            postLogoutRedirectUri: postLogoutUrl,
        });
    };
}

function isSupportedTokenType(token) {
    return typeof token === "string" && ["DPoP", "Bearer"].includes(token);
}

const USER_SESSION_PREFIX = "solidClientAuthenticationUser";

function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    }
    catch (_a) {
        return false;
    }
}
function determineSigningAlg(supported, preferred) {
    var _a;
    return ((_a = preferred.find((signingAlg) => {
        return supported.includes(signingAlg);
    })) !== null && _a !== void 0 ? _a : null);
}
function determineClientType(options, issuerConfig) {
    if (options.clientId !== undefined && !isValidUrl(options.clientId)) {
        return "static";
    }
    if (issuerConfig.scopesSupported.includes("webid") &&
        options.clientId !== undefined &&
        isValidUrl(options.clientId)) {
        return "solid-oidc";
    }
    return "dynamic";
}
async function handleRegistration(options, issuerConfig, storageUtility, clientRegistrar) {
    const clientType = determineClientType(options, issuerConfig);
    if (clientType === "dynamic") {
        return clientRegistrar.getClient({
            sessionId: options.sessionId,
            clientName: options.clientName,
            redirectUrl: options.redirectUrl,
        }, issuerConfig);
    }
    await storageUtility.setForUser(options.sessionId, {
        clientId: options.clientId,
    });
    if (options.clientSecret) {
        await storageUtility.setForUser(options.sessionId, {
            clientSecret: options.clientSecret,
        });
    }
    if (options.clientName) {
        await storageUtility.setForUser(options.sessionId, {
            clientName: options.clientName,
        });
    }
    return {
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        clientName: options.clientName,
        clientType,
    };
}

const globalFetch = (request, init) => universalFetch.fetch.call(globalThis, request, init);
class ClientAuthentication {
    constructor(loginHandler, redirectHandler, logoutHandler, sessionInfoManager, issuerConfigFetcher) {
        this.loginHandler = loginHandler;
        this.redirectHandler = redirectHandler;
        this.logoutHandler = logoutHandler;
        this.sessionInfoManager = sessionInfoManager;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.fetch = globalFetch;
        this.logout = async (sessionId, options) => {
            await this.logoutHandler.handle(sessionId, (options === null || options === void 0 ? void 0 : options.logoutType) === "idp"
                ? {
                    ...options,
                    toLogoutUrl: this.boundLogout,
                }
                : options);
            this.fetch = globalFetch;
            delete this.boundLogout;
        };
        this.getSessionInfo = async (sessionId) => {
            return this.sessionInfoManager.get(sessionId);
        };
        this.getAllSessionInfo = async () => {
            return this.sessionInfoManager.getAll();
        };
    }
}

async function getSessionIdFromOauthState(storageUtility, oauthState) {
    return storageUtility.getForUser(oauthState, "sessionId");
}
async function loadOidcContextFromStorage(sessionId, storageUtility, configFetcher) {
    try {
        const [issuerIri, codeVerifier, storedRedirectIri, dpop] = await Promise.all([
            storageUtility.getForUser(sessionId, "issuer", {
                errorIfNull: true,
            }),
            storageUtility.getForUser(sessionId, "codeVerifier"),
            storageUtility.getForUser(sessionId, "redirectUrl"),
            storageUtility.getForUser(sessionId, "dpop", { errorIfNull: true }),
        ]);
        await storageUtility.deleteForUser(sessionId, "codeVerifier");
        const issuerConfig = await configFetcher.fetchConfig(issuerIri);
        return {
            codeVerifier,
            redirectUrl: storedRedirectIri,
            issuerConfig,
            dpop: dpop === "true",
        };
    }
    catch (e) {
        throw new Error(`Failed to retrieve OIDC context from storage associated with session [${sessionId}]: ${e}`);
    }
}
async function saveSessionInfoToStorage(storageUtility, sessionId, webId, isLoggedIn, refreshToken, secure, dpopKey) {
    if (refreshToken !== undefined) {
        await storageUtility.setForUser(sessionId, { refreshToken }, { secure });
    }
    if (webId !== undefined) {
        await storageUtility.setForUser(sessionId, { webId }, { secure });
    }
    if (isLoggedIn !== undefined) {
        await storageUtility.setForUser(sessionId, { isLoggedIn }, { secure });
    }
    if (dpopKey !== undefined) {
        await storageUtility.setForUser(sessionId, {
            publicKey: JSON.stringify(dpopKey.publicKey),
            privateKey: JSON.stringify(await jose.exportJWK(dpopKey.privateKey)),
        }, { secure });
    }
}
class StorageUtility {
    constructor(secureStorage, insecureStorage) {
        this.secureStorage = secureStorage;
        this.insecureStorage = insecureStorage;
    }
    getKey(userId) {
        return `solidClientAuthenticationUser:${userId}`;
    }
    async getUserData(userId, secure) {
        const stored = await (secure
            ? this.secureStorage
            : this.insecureStorage).get(this.getKey(userId));
        if (stored === undefined) {
            return {};
        }
        try {
            return JSON.parse(stored);
        }
        catch (err) {
            throw new Error(`Data for user [${userId}] in [${secure ? "secure" : "unsecure"}] storage is corrupted - expected valid JSON, but got: ${stored}`);
        }
    }
    async setUserData(userId, data, secure) {
        await (secure ? this.secureStorage : this.insecureStorage).set(this.getKey(userId), JSON.stringify(data));
    }
    async get(key, options) {
        const value = await ((options === null || options === void 0 ? void 0 : options.secure)
            ? this.secureStorage
            : this.insecureStorage).get(key);
        if (value === undefined && (options === null || options === void 0 ? void 0 : options.errorIfNull)) {
            throw new Error(`[${key}] is not stored`);
        }
        return value;
    }
    async set(key, value, options) {
        return ((options === null || options === void 0 ? void 0 : options.secure) ? this.secureStorage : this.insecureStorage).set(key, value);
    }
    async delete(key, options) {
        return ((options === null || options === void 0 ? void 0 : options.secure) ? this.secureStorage : this.insecureStorage).delete(key);
    }
    async getForUser(userId, key, options) {
        const userData = await this.getUserData(userId, options === null || options === void 0 ? void 0 : options.secure);
        let value;
        if (!userData || !userData[key]) {
            value = undefined;
        }
        value = userData[key];
        if (value === undefined && (options === null || options === void 0 ? void 0 : options.errorIfNull)) {
            throw new Error(`Field [${key}] for user [${userId}] is not stored`);
        }
        return value || undefined;
    }
    async setForUser(userId, values, options) {
        let userData;
        try {
            userData = await this.getUserData(userId, options === null || options === void 0 ? void 0 : options.secure);
        }
        catch (_a) {
            userData = {};
        }
        await this.setUserData(userId, { ...userData, ...values }, options === null || options === void 0 ? void 0 : options.secure);
    }
    async deleteForUser(userId, key, options) {
        const userData = await this.getUserData(userId, options === null || options === void 0 ? void 0 : options.secure);
        delete userData[key];
        await this.setUserData(userId, userData, options === null || options === void 0 ? void 0 : options.secure);
    }
    async deleteAllUserData(userId, options) {
        await ((options === null || options === void 0 ? void 0 : options.secure) ? this.secureStorage : this.insecureStorage).delete(this.getKey(userId));
    }
}

class InMemoryStorage {
    constructor() {
        this.map = {};
    }
    async get(key) {
        return this.map[key] || undefined;
    }
    async set(key, value) {
        this.map[key] = value;
    }
    async delete(key) {
        delete this.map[key];
    }
}

class ConfigurationError extends Error {
    constructor(message) {
        super(message);
    }
}

class NotImplementedError extends Error {
    constructor(methodName) {
        super(`[${methodName}] is not implemented`);
    }
}

class InvalidResponseError extends Error {
    constructor(missingFields) {
        super(`Invalid response from OIDC provider: missing fields ${missingFields}`);
        this.missingFields = missingFields;
    }
}

class OidcProviderError extends Error {
    constructor(message, error, errorDescription) {
        super(message);
        this.error = error;
        this.errorDescription = errorDescription;
    }
}

function normalizeHTU(audience) {
    const audienceUrl = new URL(audience);
    return new URL(audienceUrl.pathname, audienceUrl.origin).toString();
}
async function createDpopHeader(audience, method, dpopKey) {
    return new jose.SignJWT({
        htu: normalizeHTU(audience),
        htm: method.toUpperCase(),
        jti: uuid.v4(),
    })
        .setProtectedHeader({
        alg: PREFERRED_SIGNING_ALG[0],
        jwk: dpopKey.publicKey,
        typ: "dpop+jwt",
    })
        .setIssuedAt()
        .sign(dpopKey.privateKey, {});
}
async function generateDpopKeyPair() {
    const { privateKey, publicKey } = await jose.generateKeyPair(PREFERRED_SIGNING_ALG[0]);
    const dpopKeyPair = {
        privateKey,
        publicKey: await jose.exportJWK(publicKey),
    };
    [dpopKeyPair.publicKey.alg] = PREFERRED_SIGNING_ALG;
    return dpopKeyPair;
}

const DEFAULT_EXPIRATION_TIME_SECONDS = 600;
function isExpectedAuthError(statusCode) {
    return [401, 403].includes(statusCode);
}
async function buildDpopFetchOptions(targetUrl, authToken, dpopKey, defaultOptions) {
    var _a;
    const headers = new universalFetch.Headers(defaultOptions === null || defaultOptions === void 0 ? void 0 : defaultOptions.headers);
    headers.set("Authorization", `DPoP ${authToken}`);
    headers.set("DPoP", await createDpopHeader(targetUrl, (_a = defaultOptions === null || defaultOptions === void 0 ? void 0 : defaultOptions.method) !== null && _a !== void 0 ? _a : "get", dpopKey));
    return {
        ...defaultOptions,
        headers,
    };
}
async function buildAuthenticatedHeaders(targetUrl, authToken, dpopKey, defaultOptions) {
    if (dpopKey !== undefined) {
        return buildDpopFetchOptions(targetUrl, authToken, dpopKey, defaultOptions);
    }
    const headers = new universalFetch.Headers(defaultOptions === null || defaultOptions === void 0 ? void 0 : defaultOptions.headers);
    headers.set("Authorization", `Bearer ${authToken}`);
    return {
        ...defaultOptions,
        headers,
    };
}
async function makeAuthenticatedRequest(unauthFetch, accessToken, url, defaultRequestInit, dpopKey) {
    return unauthFetch(url, await buildAuthenticatedHeaders(url.toString(), accessToken, dpopKey, defaultRequestInit));
}
async function refreshAccessToken(refreshOptions, dpopKey, eventEmitter) {
    var _a;
    const tokenSet = await refreshOptions.tokenRefresher.refresh(refreshOptions.sessionId, refreshOptions.refreshToken, dpopKey);
    eventEmitter === null || eventEmitter === void 0 ? void 0 : eventEmitter.emit(EVENTS.SESSION_EXTENDED, (_a = tokenSet.expiresIn) !== null && _a !== void 0 ? _a : DEFAULT_EXPIRATION_TIME_SECONDS);
    if (typeof tokenSet.refreshToken === "string") {
        eventEmitter === null || eventEmitter === void 0 ? void 0 : eventEmitter.emit(EVENTS.NEW_REFRESH_TOKEN, tokenSet.refreshToken);
    }
    return {
        accessToken: tokenSet.accessToken,
        refreshToken: tokenSet.refreshToken,
        expiresIn: tokenSet.expiresIn,
    };
}
const computeRefreshDelay = (expiresIn) => {
    if (expiresIn !== undefined) {
        return expiresIn - REFRESH_BEFORE_EXPIRATION_SECONDS > 0
            ?
                expiresIn - REFRESH_BEFORE_EXPIRATION_SECONDS
            : expiresIn;
    }
    return DEFAULT_EXPIRATION_TIME_SECONDS;
};
async function buildAuthenticatedFetch(unauthFetch, accessToken, options) {
    var _a;
    let currentAccessToken = accessToken;
    let latestTimeout;
    const currentRefreshOptions = options === null || options === void 0 ? void 0 : options.refreshOptions;
    if (currentRefreshOptions !== undefined) {
        const proactivelyRefreshToken = async () => {
            var _a, _b, _c, _d;
            try {
                const { accessToken: refreshedAccessToken, refreshToken, expiresIn, } = await refreshAccessToken(currentRefreshOptions, options.dpopKey, options.eventEmitter);
                currentAccessToken = refreshedAccessToken;
                if (refreshToken !== undefined) {
                    currentRefreshOptions.refreshToken = refreshToken;
                }
                clearTimeout(latestTimeout);
                latestTimeout = setTimeout(proactivelyRefreshToken, computeRefreshDelay(expiresIn) * 1000);
                (_a = options.eventEmitter) === null || _a === void 0 ? void 0 : _a.emit(EVENTS.TIMEOUT_SET, latestTimeout);
            }
            catch (e) {
                if (e instanceof OidcProviderError) {
                    (_b = options === null || options === void 0 ? void 0 : options.eventEmitter) === null || _b === void 0 ? void 0 : _b.emit(EVENTS.ERROR, e.error, e.errorDescription);
                    (_c = options === null || options === void 0 ? void 0 : options.eventEmitter) === null || _c === void 0 ? void 0 : _c.emit(EVENTS.SESSION_EXPIRED);
                }
                if (e instanceof InvalidResponseError &&
                    e.missingFields.includes("access_token")) {
                    (_d = options === null || options === void 0 ? void 0 : options.eventEmitter) === null || _d === void 0 ? void 0 : _d.emit(EVENTS.SESSION_EXPIRED);
                }
            }
        };
        latestTimeout = setTimeout(proactivelyRefreshToken, computeRefreshDelay(options.expiresIn) * 1000);
        (_a = options.eventEmitter) === null || _a === void 0 ? void 0 : _a.emit(EVENTS.TIMEOUT_SET, latestTimeout);
    }
    else if (options !== undefined && options.eventEmitter !== undefined) {
        const expirationTimeout = setTimeout(() => {
            options.eventEmitter.emit(EVENTS.SESSION_EXPIRED);
        }, computeRefreshDelay(options.expiresIn) * 1000);
        options.eventEmitter.emit(EVENTS.TIMEOUT_SET, expirationTimeout);
    }
    return async (url, requestInit) => {
        let response = await makeAuthenticatedRequest(unauthFetch, currentAccessToken, url, requestInit, options === null || options === void 0 ? void 0 : options.dpopKey);
        const failedButNotExpectedAuthError = !response.ok && !isExpectedAuthError(response.status);
        if (response.ok || failedButNotExpectedAuthError) {
            return response;
        }
        const hasBeenRedirected = response.url !== url;
        if (hasBeenRedirected && (options === null || options === void 0 ? void 0 : options.dpopKey) !== undefined) {
            response = await makeAuthenticatedRequest(unauthFetch, currentAccessToken, response.url, requestInit, options.dpopKey);
        }
        return response;
    };
}

const StorageUtilityGetResponse = "getResponse";
const StorageUtilityMock = {
    get: async (key, options) => StorageUtilityGetResponse,
    set: async (key, value) => {
    },
    delete: async (key) => {
    },
    getForUser: async (userId, key, options) => StorageUtilityGetResponse,
    setForUser: async (userId, values, options) => {
    },
    deleteForUser: async (userId, key, options) => {
    },
    deleteAllUserData: async (userId, options) => {
    },
};
const mockStorage = (stored) => {
    const store = stored;
    return {
        get: async (key) => {
            if (store[key] === undefined) {
                return undefined;
            }
            if (typeof store[key] === "string") {
                return store[key];
            }
            return JSON.stringify(store[key]);
        },
        set: async (key, value) => {
            store[key] = value;
        },
        delete: async (key) => {
            delete store[key];
        },
    };
};
const mockStorageUtility = (stored, isSecure = false) => {
    if (isSecure) {
        return new StorageUtility(mockStorage(stored), mockStorage({}));
    }
    return new StorageUtility(mockStorage({}), mockStorage(stored));
};

exports.AggregateHandler = AggregateHandler;
exports.AuthorizationCodeWithPkceOidcHandlerBase = AuthorizationCodeWithPkceOidcHandlerBase;
exports.ClientAuthentication = ClientAuthentication;
exports.ConfigurationError = ConfigurationError;
exports.DEFAULT_SCOPES = DEFAULT_SCOPES;
exports.EVENTS = EVENTS;
exports.GeneralLogoutHandler = GeneralLogoutHandler;
exports.IRpLogoutHandler = IRpLogoutHandler;
exports.IWaterfallLogoutHandler = IWaterfallLogoutHandler;
exports.InMemoryStorage = InMemoryStorage;
exports.InvalidResponseError = InvalidResponseError;
exports.NotImplementedError = NotImplementedError;
exports.OidcProviderError = OidcProviderError;
exports.PREFERRED_SIGNING_ALG = PREFERRED_SIGNING_ALG;
exports.REFRESH_BEFORE_EXPIRATION_SECONDS = REFRESH_BEFORE_EXPIRATION_SECONDS;
exports.SOLID_CLIENT_AUTHN_KEY_PREFIX = SOLID_CLIENT_AUTHN_KEY_PREFIX;
exports.SessionInfoManagerBase = SessionInfoManagerBase;
exports.StorageUtility = StorageUtility;
exports.StorageUtilityGetResponse = StorageUtilityGetResponse;
exports.StorageUtilityMock = StorageUtilityMock;
exports.USER_SESSION_PREFIX = USER_SESSION_PREFIX;
exports.buildAuthenticatedFetch = buildAuthenticatedFetch;
exports.buildProxyHandler = buildProxyHandler;
exports.clear = clear;
exports.createDpopHeader = createDpopHeader;
exports.determineSigningAlg = determineSigningAlg;
exports.fetchJwks = fetchJwks;
exports.generateDpopKeyPair = generateDpopKeyPair;
exports.getEndSessionUrl = getEndSessionUrl;
exports.getSessionIdFromOauthState = getSessionIdFromOauthState;
exports.getUnauthenticatedSession = getUnauthenticatedSession;
exports.getWebidFromTokenPayload = getWebidFromTokenPayload;
exports.handleRegistration = handleRegistration;
exports.isSupportedTokenType = isSupportedTokenType;
exports.isValidRedirectUrl = isValidRedirectUrl;
exports.loadOidcContextFromStorage = loadOidcContextFromStorage;
exports.maybeBuildRpInitiatedLogout = maybeBuildRpInitiatedLogout;
exports.mockStorage = mockStorage;
exports.mockStorageUtility = mockStorageUtility;
exports.saveSessionInfoToStorage = saveSessionInfoToStorage;
//# sourceMappingURL=index.js.map
