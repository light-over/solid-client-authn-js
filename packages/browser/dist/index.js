'use strict';

var solidClientAuthnCore = require('@inrupt/solid-client-authn-core');
var uuid = require('uuid');
var EventEmitter = require('events');
var oidcClientExt = require('@inrupt/oidc-client-ext');
var universalFetch = require('@inrupt/universal-fetch');

class StorageUtilityBrowser extends solidClientAuthnCore.StorageUtility {
    constructor(secureStorage, insecureStorage) {
        super(secureStorage, insecureStorage);
    }
}

class ClientAuthentication extends solidClientAuthnCore.ClientAuthentication {
    constructor() {
        super(...arguments);
        this.login = async (options, eventEmitter) => {
            var _a, _b;
            await this.sessionInfoManager.clear(options.sessionId);
            const redirectUrl = (_a = options.redirectUrl) !== null && _a !== void 0 ? _a : oidcClientExt.removeOidcQueryParam(window.location.href);
            if (!solidClientAuthnCore.isValidRedirectUrl(redirectUrl)) {
                throw new Error(`${redirectUrl} is not a valid redirect URL, it is either a malformed IRI or it includes a hash fragment.`);
            }
            await this.loginHandler.handle({
                ...options,
                redirectUrl,
                clientName: (_b = options.clientName) !== null && _b !== void 0 ? _b : options.clientId,
                eventEmitter,
            });
        };
        this.validateCurrentSession = async (currentSessionId) => {
            const sessionInfo = await this.sessionInfoManager.get(currentSessionId);
            if (sessionInfo === undefined ||
                sessionInfo.clientAppId === undefined ||
                sessionInfo.issuer === undefined) {
                return null;
            }
            return sessionInfo;
        };
        this.handleIncomingRedirect = async (url, eventEmitter) => {
            try {
                const redirectInfo = await this.redirectHandler.handle(url, eventEmitter);
                this.fetch = redirectInfo.fetch.bind(window);
                this.boundLogout = redirectInfo.getLogoutUrl;
                this.cleanUrlAfterRedirect(url);
                return {
                    isLoggedIn: redirectInfo.isLoggedIn,
                    webId: redirectInfo.webId,
                    sessionId: redirectInfo.sessionId,
                    expirationDate: redirectInfo.expirationDate,
                };
            }
            catch (err) {
                this.cleanUrlAfterRedirect(url);
                eventEmitter.emit(solidClientAuthnCore.EVENTS.ERROR, "redirect", err);
                return undefined;
            }
        };
    }
    cleanUrlAfterRedirect(url) {
        const cleanedUpUrl = new URL(url);
        cleanedUpUrl.searchParams.delete("state");
        cleanedUpUrl.searchParams.delete("code");
        cleanedUpUrl.searchParams.delete("id_token");
        cleanedUpUrl.searchParams.delete("access_token");
        cleanedUpUrl.searchParams.delete("error");
        cleanedUpUrl.searchParams.delete("error_description");
        cleanedUpUrl.searchParams.delete("iss");
        window.history.replaceState(null, "", cleanedUpUrl.toString());
    }
}

function hasIssuer(options) {
    return typeof options.oidcIssuer === "string";
}
function hasRedirectUrl(options) {
    return typeof options.redirectUrl === "string";
}
class OidcLoginHandler {
    constructor(storageUtility, oidcHandler, issuerConfigFetcher, clientRegistrar) {
        this.storageUtility = storageUtility;
        this.oidcHandler = oidcHandler;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.clientRegistrar = clientRegistrar;
    }
    async canHandle(options) {
        return hasIssuer(options) && hasRedirectUrl(options);
    }
    async handle(options) {
        if (!hasIssuer(options)) {
            throw new solidClientAuthnCore.ConfigurationError(`OidcLoginHandler requires an OIDC issuer: missing property 'oidcIssuer' in ${JSON.stringify(options)}`);
        }
        if (!hasRedirectUrl(options)) {
            throw new solidClientAuthnCore.ConfigurationError(`OidcLoginHandler requires a redirect URL: missing property 'redirectUrl' in ${JSON.stringify(options)}`);
        }
        const issuerConfig = await this.issuerConfigFetcher.fetchConfig(options.oidcIssuer);
        const clientRegistration = await solidClientAuthnCore.handleRegistration(options, issuerConfig, this.storageUtility, this.clientRegistrar);
        const OidcOptions = {
            issuer: issuerConfig.issuer,
            dpop: options.tokenType.toLowerCase() === "dpop",
            ...options,
            issuerConfiguration: issuerConfig,
            client: clientRegistration,
        };
        return this.oidcHandler.handle(OidcOptions);
    }
}

class AuthorizationCodeWithPkceOidcHandler extends solidClientAuthnCore.AuthorizationCodeWithPkceOidcHandlerBase {
    async handle(oidcLoginOptions) {
        var _a;
        const oidcOptions = {
            authority: oidcLoginOptions.issuer.toString(),
            client_id: oidcLoginOptions.client.clientId,
            client_secret: oidcLoginOptions.client.clientSecret,
            redirect_uri: oidcLoginOptions.redirectUrl.toString(),
            post_logout_redirect_uri: oidcLoginOptions.redirectUrl.toString(),
            response_type: "code",
            scope: solidClientAuthnCore.DEFAULT_SCOPES,
            filterProtocolClaims: true,
            loadUserInfo: false,
            code_verifier: true,
            prompt: (_a = oidcLoginOptions.prompt) !== null && _a !== void 0 ? _a : "consent",
        };
        const oidcClientLibrary = new oidcClientExt.OidcClient(oidcOptions);
        try {
            const signingRequest = await oidcClientLibrary.createSigninRequest();
            return await this.handleRedirect({
                oidcLoginOptions,
                state: signingRequest.state._id,
                codeVerifier: signingRequest.state._code_verifier,
                targetUrl: signingRequest.url.toString(),
            });
        }
        catch (err) {
            console.error(err);
        }
        return undefined;
    }
}

const WELL_KNOWN_OPENID_CONFIG = ".well-known/openid-configuration";
const issuerConfigKeyMap = {
    issuer: {
        toKey: "issuer",
        convertToUrl: true,
    },
    authorization_endpoint: {
        toKey: "authorizationEndpoint",
        convertToUrl: true,
    },
    token_endpoint: {
        toKey: "tokenEndpoint",
        convertToUrl: true,
    },
    userinfo_endpoint: {
        toKey: "userinfoEndpoint",
        convertToUrl: true,
    },
    jwks_uri: {
        toKey: "jwksUri",
        convertToUrl: true,
    },
    registration_endpoint: {
        toKey: "registrationEndpoint",
        convertToUrl: true,
    },
    end_session_endpoint: {
        toKey: "endSessionEndpoint",
        convertToUrl: true,
    },
    scopes_supported: { toKey: "scopesSupported" },
    response_types_supported: { toKey: "responseTypesSupported" },
    response_modes_supported: { toKey: "responseModesSupported" },
    grant_types_supported: { toKey: "grantTypesSupported" },
    acr_values_supported: { toKey: "acrValuesSupported" },
    subject_types_supported: { toKey: "subjectTypesSupported" },
    id_token_signing_alg_values_supported: {
        toKey: "idTokenSigningAlgValuesSupported",
    },
    id_token_encryption_alg_values_supported: {
        toKey: "idTokenEncryptionAlgValuesSupported",
    },
    id_token_encryption_enc_values_supported: {
        toKey: "idTokenEncryptionEncValuesSupported",
    },
    userinfo_signing_alg_values_supported: {
        toKey: "userinfoSigningAlgValuesSupported",
    },
    userinfo_encryption_alg_values_supported: {
        toKey: "userinfoEncryptionAlgValuesSupported",
    },
    userinfo_encryption_enc_values_supported: {
        toKey: "userinfoEncryptionEncValuesSupported",
    },
    request_object_signing_alg_values_supported: {
        toKey: "requestObjectSigningAlgValuesSupported",
    },
    request_object_encryption_alg_values_supported: {
        toKey: "requestObjectEncryptionAlgValuesSupported",
    },
    request_object_encryption_enc_values_supported: {
        toKey: "requestObjectEncryptionEncValuesSupported",
    },
    token_endpoint_auth_methods_supported: {
        toKey: "tokenEndpointAuthMethodsSupported",
    },
    token_endpoint_auth_signing_alg_values_supported: {
        toKey: "tokenEndpointAuthSigningAlgValuesSupported",
    },
    display_values_supported: { toKey: "displayValuesSupported" },
    claim_types_supported: { toKey: "claimTypesSupported" },
    claims_supported: { toKey: "claimsSupported" },
    service_documentation: { toKey: "serviceDocumentation" },
    claims_locales_supported: { toKey: "claimsLocalesSupported" },
    ui_locales_supported: { toKey: "uiLocalesSupported" },
    claims_parameter_supported: { toKey: "claimsParameterSupported" },
    request_parameter_supported: { toKey: "requestParameterSupported" },
    request_uri_parameter_supported: { toKey: "requestUriParameterSupported" },
    require_request_uri_registration: { toKey: "requireRequestUriRegistration" },
    op_policy_uri: {
        toKey: "opPolicyUri",
        convertToUrl: true,
    },
    op_tos_uri: {
        toKey: "opTosUri",
        convertToUrl: true,
    },
};
function processConfig(config) {
    const parsedConfig = {};
    Object.keys(config).forEach((key) => {
        if (issuerConfigKeyMap[key]) {
            parsedConfig[issuerConfigKeyMap[key].toKey] = config[key];
        }
    });
    if (!Array.isArray(parsedConfig.scopesSupported)) {
        parsedConfig.scopesSupported = ["openid"];
    }
    return parsedConfig;
}
class IssuerConfigFetcher {
    constructor(storageUtility) {
        this.storageUtility = storageUtility;
    }
    static getLocalStorageKey(issuer) {
        return `issuerConfig:${issuer}`;
    }
    async fetchConfig(issuer) {
        let issuerConfig;
        const openIdConfigUrl = new URL(WELL_KNOWN_OPENID_CONFIG, issuer.endsWith("/") ? issuer : `${issuer}/`).href;
        const issuerConfigRequestBody = await universalFetch.fetch.call(globalThis, openIdConfigUrl);
        try {
            issuerConfig = processConfig(await issuerConfigRequestBody.json());
        }
        catch (err) {
            throw new solidClientAuthnCore.ConfigurationError(`[${issuer.toString()}] has an invalid configuration: ${err.message}`);
        }
        await this.storageUtility.set(IssuerConfigFetcher.getLocalStorageKey(issuer), JSON.stringify(issuerConfig));
        return issuerConfig;
    }
}

async function clear(sessionId, storage) {
    await solidClientAuthnCore.clear(sessionId, storage);
    await oidcClientExt.clearOidcPersistentStorage();
}
class SessionInfoManager extends solidClientAuthnCore.SessionInfoManagerBase {
    async get(sessionId) {
        var _a;
        const isLoggedIn = await this.storageUtility.getForUser(sessionId, "isLoggedIn", {
            secure: true,
        });
        const webId = await this.storageUtility.getForUser(sessionId, "webId", {
            secure: true,
        });
        const clientId = await this.storageUtility.getForUser(sessionId, "clientId", {
            secure: false,
        });
        const clientSecret = await this.storageUtility.getForUser(sessionId, "clientSecret", {
            secure: false,
        });
        const redirectUrl = await this.storageUtility.getForUser(sessionId, "redirectUrl", {
            secure: false,
        });
        const refreshToken = await this.storageUtility.getForUser(sessionId, "refreshToken", {
            secure: true,
        });
        const issuer = await this.storageUtility.getForUser(sessionId, "issuer", {
            secure: false,
        });
        const tokenType = (_a = (await this.storageUtility.getForUser(sessionId, "tokenType", {
            secure: false,
        }))) !== null && _a !== void 0 ? _a : "DPoP";
        if (!solidClientAuthnCore.isSupportedTokenType(tokenType)) {
            throw new Error(`Tokens of type [${tokenType}] are not supported.`);
        }
        if (clientId === undefined &&
            isLoggedIn === undefined &&
            webId === undefined &&
            refreshToken === undefined) {
            return undefined;
        }
        return {
            sessionId,
            webId,
            isLoggedIn: isLoggedIn === "true",
            redirectUrl,
            refreshToken,
            issuer,
            clientAppId: clientId,
            clientAppSecret: clientSecret,
            tokenType,
        };
    }
    async clear(sessionId) {
        return clear(sessionId, this.storageUtility);
    }
}

class FallbackRedirectHandler {
    async canHandle(redirectUrl) {
        try {
            new URL(redirectUrl);
            return true;
        }
        catch (e) {
            throw new Error(`[${redirectUrl}] is not a valid URL, and cannot be used as a redirect URL: ${e}`);
        }
    }
    async handle(_redirectUrl) {
        return solidClientAuthnCore.getUnauthenticatedSession();
    }
}

const globalFetch = (...args) => universalFetch.fetch.call(globalThis, ...args);
class AuthCodeRedirectHandler {
    constructor(storageUtility, sessionInfoManager, issuerConfigFetcher, clientRegistrar, tokerRefresher) {
        this.storageUtility = storageUtility;
        this.sessionInfoManager = sessionInfoManager;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.clientRegistrar = clientRegistrar;
        this.tokerRefresher = tokerRefresher;
    }
    async canHandle(redirectUrl) {
        try {
            const myUrl = new URL(redirectUrl);
            return (myUrl.searchParams.get("code") !== null &&
                myUrl.searchParams.get("state") !== null);
        }
        catch (e) {
            throw new Error(`[${redirectUrl}] is not a valid URL, and cannot be used as a redirect URL: ${e}`);
        }
    }
    async handle(redirectUrl, eventEmitter) {
        if (!(await this.canHandle(redirectUrl))) {
            throw new Error(`AuthCodeRedirectHandler cannot handle [${redirectUrl}]: it is missing one of [code, state].`);
        }
        const url = new URL(redirectUrl);
        const oauthState = url.searchParams.get("state");
        const storedSessionId = (await this.storageUtility.getForUser(oauthState, "sessionId", {
            errorIfNull: true,
        }));
        const { issuerConfig, codeVerifier, redirectUrl: storedRedirectIri, dpop: isDpop, } = await solidClientAuthnCore.loadOidcContextFromStorage(storedSessionId, this.storageUtility, this.issuerConfigFetcher);
        const iss = url.searchParams.get("iss");
        if (typeof iss === "string" && iss !== issuerConfig.issuer) {
            throw new Error(`The value of the iss parameter (${iss}) does not match the issuer identifier of the authorization server (${issuerConfig.issuer}). See [rfc9207](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.3-3.1.1)`);
        }
        if (codeVerifier === undefined) {
            throw new Error(`The code verifier for session ${storedSessionId} is missing from storage.`);
        }
        if (storedRedirectIri === undefined) {
            throw new Error(`The redirect URL for session ${storedSessionId} is missing from storage.`);
        }
        const client = await this.clientRegistrar.getClient({ sessionId: storedSessionId }, issuerConfig);
        let tokens;
        const tokenCreatedAt = Date.now();
        if (isDpop) {
            tokens = await oidcClientExt.getDpopToken(issuerConfig, client, {
                grantType: "authorization_code",
                code: url.searchParams.get("code"),
                codeVerifier,
                redirectUrl: storedRedirectIri,
            });
            window.localStorage.removeItem(`oidc.${oauthState}`);
        }
        else {
            tokens = await oidcClientExt.getBearerToken(url.toString());
        }
        let refreshOptions;
        if (tokens.refreshToken !== undefined) {
            refreshOptions = {
                sessionId: storedSessionId,
                refreshToken: tokens.refreshToken,
                tokenRefresher: this.tokerRefresher,
            };
        }
        const authFetch = await solidClientAuthnCore.buildAuthenticatedFetch(globalFetch, tokens.accessToken, {
            dpopKey: tokens.dpopKey,
            refreshOptions,
            eventEmitter,
            expiresIn: tokens.expiresIn,
        });
        await this.storageUtility.setForUser(storedSessionId, {
            webId: tokens.webId,
            isLoggedIn: "true",
        }, { secure: true });
        const sessionInfo = await this.sessionInfoManager.get(storedSessionId);
        if (!sessionInfo) {
            throw new Error(`Could not retrieve session: [${storedSessionId}].`);
        }
        return Object.assign(sessionInfo, {
            fetch: authFetch,
            getLogoutUrl: solidClientAuthnCore.maybeBuildRpInitiatedLogout({
                idTokenHint: tokens.idToken,
                endSessionEndpoint: issuerConfig.endSessionEndpoint,
            }),
            expirationDate: typeof tokens.expiresIn === "number"
                ? tokenCreatedAt + tokens.expiresIn * 1000
                : undefined,
        });
    }
}

class AggregateRedirectHandler extends solidClientAuthnCore.AggregateHandler {
    constructor(redirectHandlers) {
        super(redirectHandlers);
    }
}

class BrowserStorage {
    get storage() {
        return window.localStorage;
    }
    async get(key) {
        return this.storage.getItem(key) || undefined;
    }
    async set(key, value) {
        this.storage.setItem(key, value);
    }
    async delete(key) {
        this.storage.removeItem(key);
    }
}

class Redirector {
    redirect(redirectUrl, options) {
        if (options && options.handleRedirect) {
            options.handleRedirect(redirectUrl);
        }
        else if (options && options.redirectByReplacingState) {
            window.history.replaceState({}, "", redirectUrl);
        }
        else {
            window.location.href = redirectUrl;
        }
    }
}

class ClientRegistrar {
    constructor(storageUtility) {
        this.storageUtility = storageUtility;
    }
    async getClient(options, issuerConfig) {
        const [storedClientId, storedClientSecret,] = await Promise.all([
            this.storageUtility.getForUser(options.sessionId, "clientId", {
                secure: false,
            }),
            this.storageUtility.getForUser(options.sessionId, "clientSecret", {
                secure: false,
            }),
        ]);
        if (storedClientId) {
            return {
                clientId: storedClientId,
                clientSecret: storedClientSecret,
                clientType: "dynamic",
            };
        }
        try {
            const registeredClient = await oidcClientExt.registerClient(options, issuerConfig);
            const infoToSave = {
                clientId: registeredClient.clientId,
            };
            if (registeredClient.clientSecret) {
                infoToSave.clientSecret = registeredClient.clientSecret;
            }
            if (registeredClient.idTokenSignedResponseAlg) {
                infoToSave.idTokenSignedResponseAlg =
                    registeredClient.idTokenSignedResponseAlg;
            }
            await this.storageUtility.setForUser(options.sessionId, infoToSave, {
                secure: false,
            });
            return registeredClient;
        }
        catch (error) {
            throw new Error(`Client registration failed: [${error}]`);
        }
    }
}

class ErrorOidcHandler {
    async canHandle(redirectUrl) {
        try {
            return new URL(redirectUrl).searchParams.has("error");
        }
        catch (e) {
            throw new Error(`[${redirectUrl}] is not a valid URL, and cannot be used as a redirect URL: ${e}`);
        }
    }
    async handle(redirectUrl, eventEmitter) {
        if (eventEmitter !== undefined) {
            const url = new URL(redirectUrl);
            const errorUrl = url.searchParams.get("error");
            const errorDescriptionUrl = url.searchParams.get("error_description");
            eventEmitter.emit(solidClientAuthnCore.EVENTS.ERROR, errorUrl, errorDescriptionUrl);
        }
        return solidClientAuthnCore.getUnauthenticatedSession();
    }
}

class TokenRefresher {
    constructor(storageUtility, issuerConfigFetcher, clientRegistrar) {
        this.storageUtility = storageUtility;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.clientRegistrar = clientRegistrar;
    }
    async refresh(sessionId, refreshToken, dpopKey, eventEmitter) {
        const oidcContext = await solidClientAuthnCore.loadOidcContextFromStorage(sessionId, this.storageUtility, this.issuerConfigFetcher);
        const clientInfo = await this.clientRegistrar.getClient({ sessionId }, oidcContext.issuerConfig);
        if (refreshToken === undefined) {
            throw new Error(`Session [${sessionId}] has no refresh token to allow it to refresh its access token.`);
        }
        if (oidcContext.dpop && dpopKey === undefined) {
            throw new Error(`For session [${sessionId}], the key bound to the DPoP access token must be provided to refresh said access token.`);
        }
        const tokenSet = await oidcClientExt.refresh(refreshToken, oidcContext.issuerConfig, clientInfo, dpopKey);
        if (tokenSet.refreshToken !== undefined) {
            eventEmitter === null || eventEmitter === void 0 ? void 0 : eventEmitter.emit(solidClientAuthnCore.EVENTS.NEW_REFRESH_TOKEN, tokenSet.refreshToken);
            await this.storageUtility.setForUser(sessionId, {
                refreshToken: tokenSet.refreshToken,
            });
        }
        return tokenSet;
    }
}

function getClientAuthenticationWithDependencies(dependencies) {
    const inMemoryStorage = new solidClientAuthnCore.InMemoryStorage();
    const secureStorage = dependencies.secureStorage || inMemoryStorage;
    const insecureStorage = dependencies.insecureStorage || new BrowserStorage();
    const storageUtility = new StorageUtilityBrowser(secureStorage, insecureStorage);
    const issuerConfigFetcher = new IssuerConfigFetcher(storageUtility);
    const clientRegistrar = new ClientRegistrar(storageUtility);
    const sessionInfoManager = new SessionInfoManager(storageUtility);
    const tokenRefresher = new TokenRefresher(storageUtility, issuerConfigFetcher, clientRegistrar);
    const redirector = new Redirector();
    const loginHandler = new OidcLoginHandler(storageUtility, new AuthorizationCodeWithPkceOidcHandler(storageUtility, redirector), issuerConfigFetcher, clientRegistrar);
    const redirectHandler = new AggregateRedirectHandler([
        new ErrorOidcHandler(),
        new AuthCodeRedirectHandler(storageUtility, sessionInfoManager, issuerConfigFetcher, clientRegistrar, tokenRefresher),
        new FallbackRedirectHandler(),
    ]);
    return new ClientAuthentication(loginHandler, redirectHandler, new solidClientAuthnCore.IWaterfallLogoutHandler(sessionInfoManager, redirector), sessionInfoManager, issuerConfigFetcher);
}

const KEY_CURRENT_SESSION = `${solidClientAuthnCore.SOLID_CLIENT_AUTHN_KEY_PREFIX}currentSession`;
const KEY_CURRENT_URL = `${solidClientAuthnCore.SOLID_CLIENT_AUTHN_KEY_PREFIX}currentUrl`;

async function silentlyAuthenticate(sessionId, clientAuthn, session) {
    var _a;
    const storedSessionInfo = await clientAuthn.validateCurrentSession(sessionId);
    if (storedSessionInfo !== null) {
        window.localStorage.setItem(KEY_CURRENT_URL, window.location.href);
        await clientAuthn.login({
            sessionId,
            prompt: "none",
            oidcIssuer: storedSessionInfo.issuer,
            redirectUrl: storedSessionInfo.redirectUrl,
            clientId: storedSessionInfo.clientAppId,
            clientSecret: storedSessionInfo.clientAppSecret,
            tokenType: (_a = storedSessionInfo.tokenType) !== null && _a !== void 0 ? _a : "DPoP",
        }, session.events);
        return true;
    }
    return false;
}
function isLoggedIn(sessionInfo) {
    return !!(sessionInfo === null || sessionInfo === void 0 ? void 0 : sessionInfo.isLoggedIn);
}
class Session extends EventEmitter {
    constructor(sessionOptions = {}, sessionId = undefined) {
        super();
        this.tokenRequestInProgress = false;
        this.login = async (options) => {
            var _a;
            await this.clientAuthentication.login({
                sessionId: this.info.sessionId,
                ...options,
                tokenType: (_a = options.tokenType) !== null && _a !== void 0 ? _a : "DPoP",
            }, this.events);
            return new Promise(() => { });
        };
        this.fetch = (url, init) => this.clientAuthentication.fetch(url, init);
        this.internalLogout = async (emitSignal, options) => {
            window.localStorage.removeItem(KEY_CURRENT_SESSION);
            await this.clientAuthentication.logout(this.info.sessionId, options);
            this.info.isLoggedIn = false;
            if (emitSignal) {
                this.events.emit(solidClientAuthnCore.EVENTS.LOGOUT);
            }
        };
        this.logout = async (options) => this.internalLogout(true, options);
        this.handleIncomingRedirect = async (inputOptions = {}) => {
            var _a;
            if (this.info.isLoggedIn) {
                return this.info;
            }
            if (this.tokenRequestInProgress) {
                return undefined;
            }
            const options = typeof inputOptions === "string" ? { url: inputOptions } : inputOptions;
            const url = (_a = options.url) !== null && _a !== void 0 ? _a : window.location.href;
            this.tokenRequestInProgress = true;
            const sessionInfo = await this.clientAuthentication.handleIncomingRedirect(url, this.events);
            if (isLoggedIn(sessionInfo)) {
                this.setSessionInfo(sessionInfo);
                const currentUrl = window.localStorage.getItem(KEY_CURRENT_URL);
                if (currentUrl === null) {
                    this.events.emit(solidClientAuthnCore.EVENTS.LOGIN);
                }
                else {
                    window.localStorage.removeItem(KEY_CURRENT_URL);
                    this.events.emit(solidClientAuthnCore.EVENTS.SESSION_RESTORED, currentUrl);
                }
            }
            else if (options.restorePreviousSession === true) {
                const storedSessionId = window.localStorage.getItem(KEY_CURRENT_SESSION);
                if (storedSessionId !== null) {
                    const attemptedSilentAuthentication = await silentlyAuthenticate(storedSessionId, this.clientAuthentication, this);
                    if (attemptedSilentAuthentication) {
                        return new Promise(() => { });
                    }
                }
            }
            this.tokenRequestInProgress = false;
            return sessionInfo;
        };
        this.events = new Proxy(this, solidClientAuthnCore.buildProxyHandler(Session.prototype, "events only implements ISessionEventListener"));
        if (sessionOptions.clientAuthentication) {
            this.clientAuthentication = sessionOptions.clientAuthentication;
        }
        else if (sessionOptions.secureStorage && sessionOptions.insecureStorage) {
            this.clientAuthentication = getClientAuthenticationWithDependencies({
                secureStorage: sessionOptions.secureStorage,
                insecureStorage: sessionOptions.insecureStorage,
            });
        }
        else {
            this.clientAuthentication = getClientAuthenticationWithDependencies({});
        }
        if (sessionOptions.sessionInfo) {
            this.info = {
                sessionId: sessionOptions.sessionInfo.sessionId,
                isLoggedIn: false,
                webId: sessionOptions.sessionInfo.webId,
            };
        }
        else {
            this.info = {
                sessionId: sessionId !== null && sessionId !== void 0 ? sessionId : uuid.v4(),
                isLoggedIn: false,
            };
        }
        this.events.on(solidClientAuthnCore.EVENTS.LOGIN, () => window.localStorage.setItem(KEY_CURRENT_SESSION, this.info.sessionId));
        this.events.on(solidClientAuthnCore.EVENTS.SESSION_EXPIRED, () => this.internalLogout(false));
        this.events.on(solidClientAuthnCore.EVENTS.ERROR, () => this.internalLogout(false));
    }
    onLogin(callback) {
        this.events.on(solidClientAuthnCore.EVENTS.LOGIN, callback);
    }
    onLogout(callback) {
        this.events.on(solidClientAuthnCore.EVENTS.LOGOUT, callback);
    }
    onError(callback) {
        this.events.on(solidClientAuthnCore.EVENTS.ERROR, callback);
    }
    onSessionRestore(callback) {
        this.events.on(solidClientAuthnCore.EVENTS.SESSION_RESTORED, callback);
    }
    onSessionExpiration(callback) {
        this.events.on(solidClientAuthnCore.EVENTS.SESSION_EXPIRED, callback);
    }
    setSessionInfo(sessionInfo) {
        this.info.isLoggedIn = sessionInfo.isLoggedIn;
        this.info.webId = sessionInfo.webId;
        this.info.sessionId = sessionInfo.sessionId;
        this.info.expirationDate = sessionInfo.expirationDate;
        this.events.on(solidClientAuthnCore.EVENTS.SESSION_EXTENDED, (expiresIn) => {
            this.info.expirationDate = Date.now() + expiresIn * 1000;
        });
    }
}

let defaultSession;
function getDefaultSession() {
    if (typeof defaultSession === "undefined") {
        defaultSession = new Session();
    }
    return defaultSession;
}
const fetch = (...args) => {
    const session = getDefaultSession();
    return session.fetch(...args);
};
const login = (...args) => {
    const session = getDefaultSession();
    return session.login(...args);
};
const logout = (...args) => {
    const session = getDefaultSession();
    return session.logout(...args);
};
const handleIncomingRedirect = (...args) => {
    const session = getDefaultSession();
    return session.handleIncomingRedirect(...args);
};
const onLogin = (...args) => {
    const session = getDefaultSession();
    return session.onLogin(...args);
};
const onLogout = (...args) => {
    const session = getDefaultSession();
    return session.onLogout(...args);
};
const onSessionRestore = (...args) => {
    const session = getDefaultSession();
    return session.onSessionRestore(...args);
};
const events = () => {
    return getDefaultSession().events;
};

Object.defineProperty(exports, 'ConfigurationError', {
  enumerable: true,
  get: function () { return solidClientAuthnCore.ConfigurationError; }
});
Object.defineProperty(exports, 'EVENTS', {
  enumerable: true,
  get: function () { return solidClientAuthnCore.EVENTS; }
});
Object.defineProperty(exports, 'InMemoryStorage', {
  enumerable: true,
  get: function () { return solidClientAuthnCore.InMemoryStorage; }
});
Object.defineProperty(exports, 'NotImplementedError', {
  enumerable: true,
  get: function () { return solidClientAuthnCore.NotImplementedError; }
});
exports.Session = Session;
exports.events = events;
exports.fetch = fetch;
exports.getClientAuthenticationWithDependencies = getClientAuthenticationWithDependencies;
exports.getDefaultSession = getDefaultSession;
exports.handleIncomingRedirect = handleIncomingRedirect;
exports.login = login;
exports.logout = logout;
exports.onLogin = onLogin;
exports.onLogout = onLogout;
exports.onSessionRestore = onSessionRestore;
//# sourceMappingURL=index.js.map
