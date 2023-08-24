import { StorageUtility, ClientAuthentication as ClientAuthentication$1, isValidRedirectUrl, ConfigurationError, handleRegistration, AggregateHandler, AuthorizationCodeWithPkceOidcHandlerBase, DEFAULT_SCOPES, PREFERRED_SIGNING_ALG, getWebidFromTokenPayload, saveSessionInfoToStorage, generateDpopKeyPair, buildAuthenticatedFetch, SOLID_CLIENT_AUTHN_KEY_PREFIX, SessionInfoManagerBase, getSessionIdFromOauthState, loadOidcContextFromStorage, EVENTS, maybeBuildRpInitiatedLogout, getUnauthenticatedSession, determineSigningAlg, InMemoryStorage, IWaterfallLogoutHandler, buildProxyHandler } from '@inrupt/solid-client-authn-core';
export { ConfigurationError, EVENTS, InMemoryStorage, NotImplementedError } from '@inrupt/solid-client-authn-core';
import { v4 } from 'uuid';
import { fetch } from '@inrupt/universal-fetch';
import EventEmitter from 'events';
import { Issuer, generators } from 'openid-client';
import { importJWK } from 'jose';
import { URL } from 'url';

class StorageUtilityNode extends StorageUtility {
    constructor(secureStorage, insecureStorage) {
        super(secureStorage, insecureStorage);
    }
}

class ClientAuthentication extends ClientAuthentication$1 {
    constructor() {
        super(...arguments);
        this.login = async (sessionId, options, eventEmitter) => {
            var _a, _b;
            await this.sessionInfoManager.register(sessionId);
            if (typeof options.redirectUrl === "string" &&
                !isValidRedirectUrl(options.redirectUrl)) {
                throw new Error(`${options.redirectUrl} is not a valid redirect URL, it is either a malformed IRI or it includes a hash fragment.`);
            }
            const loginReturn = await this.loginHandler.handle({
                sessionId,
                oidcIssuer: options.oidcIssuer,
                redirectUrl: options.redirectUrl,
                clientId: options.clientId,
                clientSecret: options.clientSecret,
                clientName: (_a = options.clientName) !== null && _a !== void 0 ? _a : options.clientId,
                refreshToken: options.refreshToken,
                handleRedirect: options.handleRedirect,
                tokenType: (_b = options.tokenType) !== null && _b !== void 0 ? _b : "DPoP",
                eventEmitter,
            });
            if (loginReturn !== undefined) {
                this.fetch = loginReturn.fetch;
                return loginReturn;
            }
            return undefined;
        };
        this.getSessionIdAll = async () => {
            return this.sessionInfoManager.getRegisteredSessionIdAll();
        };
        this.registerSession = async (sessionId) => {
            return this.sessionInfoManager.register(sessionId);
        };
        this.clearSessionAll = async () => {
            return this.sessionInfoManager.clearAll();
        };
        this.handleIncomingRedirect = async (url, eventEmitter) => {
            const redirectInfo = await this.redirectHandler.handle(url, eventEmitter);
            this.fetch = redirectInfo.fetch;
            this.boundLogout = redirectInfo.getLogoutUrl;
            return {
                isLoggedIn: redirectInfo.isLoggedIn,
                webId: redirectInfo.webId,
                sessionId: redirectInfo.sessionId,
            };
        };
    }
}

function hasIssuer(options) {
    return typeof options.oidcIssuer === "string";
}
class OidcLoginHandler {
    constructor(storageUtility, oidcHandler, issuerConfigFetcher, clientRegistrar) {
        this.storageUtility = storageUtility;
        this.oidcHandler = oidcHandler;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.clientRegistrar = clientRegistrar;
    }
    async canHandle(options) {
        return hasIssuer(options);
    }
    async handle(options) {
        var _a;
        if (!hasIssuer(options)) {
            throw new ConfigurationError(`OidcLoginHandler requires an OIDC issuer: missing property 'oidcIssuer' in ${JSON.stringify(options)}`);
        }
        const issuerConfig = await this.issuerConfigFetcher.fetchConfig(options.oidcIssuer);
        const clientInfo = await handleRegistration(options, issuerConfig, this.storageUtility, this.clientRegistrar);
        const oidcOptions = {
            issuer: issuerConfig.issuer,
            dpop: options.tokenType.toLowerCase() === "dpop",
            redirectUrl: options.redirectUrl,
            issuerConfiguration: issuerConfig,
            client: clientInfo,
            sessionId: options.sessionId,
            refreshToken: (_a = options.refreshToken) !== null && _a !== void 0 ? _a : (await this.storageUtility.getForUser(options.sessionId, "refreshToken")),
            handleRedirect: options.handleRedirect,
            eventEmitter: options.eventEmitter,
        };
        return this.oidcHandler.handle(oidcOptions);
    }
}

class AggregateOidcHandler extends AggregateHandler {
    constructor(oidcLoginHandlers) {
        super(oidcLoginHandlers);
    }
}

function configFromIssuerMetadata(metadata) {
    if (metadata.authorization_endpoint === undefined) {
        throw new ConfigurationError(`Issuer metadata is missing an authorization endpoint: ${JSON.stringify(metadata)}`);
    }
    if (metadata.token_endpoint === undefined) {
        throw new ConfigurationError(`Issuer metadata is missing an token endpoint: ${JSON.stringify(metadata)}`);
    }
    if (metadata.jwks_uri === undefined) {
        throw new ConfigurationError(`Issuer metadata is missing a keyset URI: ${JSON.stringify(metadata)}`);
    }
    if (metadata.claims_supported === undefined) {
        throw new ConfigurationError(`Issuer metadata is missing supported claims: ${JSON.stringify(metadata)}`);
    }
    if (metadata.subject_types_supported === undefined) {
        throw new ConfigurationError(`Issuer metadata is missing supported subject types: ${JSON.stringify(metadata)}`);
    }
    return {
        issuer: metadata.issuer,
        authorizationEndpoint: metadata.authorization_endpoint,
        subjectTypesSupported: metadata.subject_types_supported,
        claimsSupported: metadata.claims_supported,
        tokenEndpoint: metadata.token_endpoint,
        jwksUri: metadata.jwks_uri,
        userinfoEndpoint: metadata.userinfo_endpoint,
        registrationEndpoint: metadata.registration_endpoint,
        tokenEndpointAuthMethodsSupported: metadata.token_endpoint_auth_methods_supported,
        tokenEndpointAuthSigningAlgValuesSupported: metadata.token_endpoint_auth_signing_alg_values_supported,
        requestObjectSigningAlgValuesSupported: metadata.request_object_signing_alg_values_supported,
        grantTypesSupported: metadata.grant_types_supported,
        responseTypesSupported: metadata.response_types_supported,
        idTokenSigningAlgValuesSupported: metadata.id_token_signing_alg_values_supported,
        scopesSupported: metadata.scopes_supported === undefined
            ? ["openid"]
            : metadata.scopes_supported,
        endSessionEndpoint: metadata.end_session_endpoint,
    };
}
function configToIssuerMetadata(config) {
    return {
        issuer: config.issuer,
        authorization_endpoint: config.authorizationEndpoint,
        jwks_uri: config.jwksUri,
        token_endpoint: config.tokenEndpoint,
        registration_endpoint: config.registrationEndpoint,
        subject_types_supported: config.subjectTypesSupported,
        claims_supported: config.claimsSupported,
        token_endpoint_auth_signing_alg_values_supported: config.tokenEndpointAuthSigningAlgValuesSupported,
        userinfo_endpoint: config.userinfoEndpoint,
        token_endpoint_auth_methods_supported: config.tokenEndpointAuthMethodsSupported,
        request_object_signing_alg_values_supported: config.requestObjectSigningAlgValuesSupported,
        grant_types_supported: config.grantTypesSupported,
        response_types_supported: config.responseTypesSupported,
        id_token_signing_alg_values_supported: config.idTokenSigningAlgValuesSupported,
        scopes_supported: config.scopesSupported,
        end_session_endpoint: config.endSessionEndpoint,
    };
}
class IssuerConfigFetcher {
    constructor(storageUtility) {
        this.storageUtility = storageUtility;
    }
    static getLocalStorageKey(issuer) {
        return `issuerConfig:${issuer}`;
    }
    async fetchConfig(issuer) {
        const oidcIssuer = await Issuer.discover(issuer);
        const issuerConfig = configFromIssuerMetadata(oidcIssuer.metadata);
        await this.storageUtility.set(IssuerConfigFetcher.getLocalStorageKey(issuer), JSON.stringify(issuerConfig));
        return issuerConfig;
    }
}

class AuthorizationCodeWithPkceOidcHandler extends AuthorizationCodeWithPkceOidcHandlerBase {
    async handle(oidcLoginOptions) {
        const issuer = new Issuer(configToIssuerMetadata(oidcLoginOptions.issuerConfiguration));
        const client = new issuer.Client({
            client_id: oidcLoginOptions.client.clientId,
            client_secret: oidcLoginOptions.client.clientSecret,
        });
        const codeVerifier = generators.codeVerifier();
        const state = generators.state();
        const targetUrl = client.authorizationUrl({
            code_challenge: generators.codeChallenge(codeVerifier),
            state,
            response_type: "code",
            redirect_uri: oidcLoginOptions.redirectUrl,
            code_challenge_method: "S256",
            prompt: "consent",
            scope: DEFAULT_SCOPES,
        });
        return this.handleRedirect({
            oidcLoginOptions,
            state,
            codeVerifier,
            targetUrl,
        });
    }
}

function validateOptions(oidcLoginOptions) {
    return (oidcLoginOptions.refreshToken !== undefined &&
        oidcLoginOptions.client.clientId !== undefined);
}
async function refreshAccess(refreshOptions, dpop, refreshBindingKey, eventEmitter) {
    var _a;
    try {
        let dpopKey;
        if (dpop) {
            dpopKey = refreshBindingKey || (await generateDpopKeyPair());
            [dpopKey.publicKey.alg] = PREFERRED_SIGNING_ALG;
        }
        const tokens = await refreshOptions.tokenRefresher.refresh(refreshOptions.sessionId, refreshOptions.refreshToken, dpopKey);
        const rotatedRefreshOptions = {
            ...refreshOptions,
            refreshToken: (_a = tokens.refreshToken) !== null && _a !== void 0 ? _a : refreshOptions.refreshToken,
        };
        const authFetch = await buildAuthenticatedFetch(fetch, tokens.accessToken, {
            dpopKey,
            refreshOptions: rotatedRefreshOptions,
            eventEmitter,
        });
        return Object.assign(tokens, {
            fetch: authFetch,
        });
    }
    catch (e) {
        throw new Error(`Invalid refresh credentials: ${e}`);
    }
}
class RefreshTokenOidcHandler {
    constructor(tokenRefresher, storageUtility) {
        this.tokenRefresher = tokenRefresher;
        this.storageUtility = storageUtility;
    }
    async canHandle(oidcLoginOptions) {
        return validateOptions(oidcLoginOptions);
    }
    async handle(oidcLoginOptions) {
        var _a;
        if (!(await this.canHandle(oidcLoginOptions))) {
            throw new Error(`RefreshTokenOidcHandler cannot handle the provided options, missing one of 'refreshToken', 'clientId' in: ${JSON.stringify(oidcLoginOptions)}`);
        }
        const refreshOptions = {
            refreshToken: oidcLoginOptions.refreshToken,
            sessionId: oidcLoginOptions.sessionId,
            tokenRefresher: this.tokenRefresher,
        };
        await this.storageUtility.setForUser(oidcLoginOptions.sessionId, {
            issuer: oidcLoginOptions.issuer,
            dpop: oidcLoginOptions.dpop ? "true" : "false",
            clientId: oidcLoginOptions.client.clientId,
            clientSecret: oidcLoginOptions.client.clientSecret,
        });
        const publicKey = await this.storageUtility.getForUser(oidcLoginOptions.sessionId, "publicKey");
        const privateKey = await this.storageUtility.getForUser(oidcLoginOptions.sessionId, "privateKey");
        let keyPair;
        if (publicKey !== undefined && privateKey !== undefined) {
            keyPair = {
                publicKey: JSON.parse(publicKey),
                privateKey: (await importJWK(JSON.parse(privateKey), PREFERRED_SIGNING_ALG[0])),
            };
        }
        const accessInfo = await refreshAccess(refreshOptions, oidcLoginOptions.dpop, keyPair);
        const sessionInfo = {
            isLoggedIn: true,
            sessionId: oidcLoginOptions.sessionId,
        };
        if (accessInfo.idToken === undefined) {
            throw new Error(`The Identity Provider [${oidcLoginOptions.issuer}] did not return an ID token on refresh, which prevents us from getting the user's WebID.`);
        }
        sessionInfo.webId = await getWebidFromTokenPayload(accessInfo.idToken, oidcLoginOptions.issuerConfiguration.jwksUri, oidcLoginOptions.issuer, oidcLoginOptions.client.clientId);
        await saveSessionInfoToStorage(this.storageUtility, oidcLoginOptions.sessionId, undefined, "true", (_a = accessInfo.refreshToken) !== null && _a !== void 0 ? _a : refreshOptions.refreshToken, undefined, keyPair);
        await this.storageUtility.setForUser(oidcLoginOptions.sessionId, {
            issuer: oidcLoginOptions.issuer,
            dpop: oidcLoginOptions.dpop ? "true" : "false",
            clientId: oidcLoginOptions.client.clientId,
        });
        if (oidcLoginOptions.client.clientSecret) {
            await this.storageUtility.setForUser(oidcLoginOptions.sessionId, {
                clientSecret: oidcLoginOptions.client.clientSecret,
            });
        }
        if (oidcLoginOptions.client.clientName) {
            await this.storageUtility.setForUser(oidcLoginOptions.sessionId, {
                clientName: oidcLoginOptions.client.clientName,
            });
        }
        let expirationDate;
        expirationDate = accessInfo.expiresAt;
        if (expirationDate === undefined && accessInfo.expiresIn !== undefined) {
            expirationDate = accessInfo.expiresIn + Date.now();
        }
        sessionInfo.expirationDate = expirationDate;
        return Object.assign(sessionInfo, {
            fetch: accessInfo.fetch,
        });
    }
}

const KEY_REGISTERED_SESSIONS = `${SOLID_CLIENT_AUTHN_KEY_PREFIX}registeredSessions`;

class SessionInfoManager extends SessionInfoManagerBase {
    async get(sessionId) {
        const webId = await this.storageUtility.getForUser(sessionId, "webId");
        const isLoggedIn = await this.storageUtility.getForUser(sessionId, "isLoggedIn");
        const refreshToken = await this.storageUtility.getForUser(sessionId, "refreshToken");
        const issuer = await this.storageUtility.getForUser(sessionId, "issuer");
        if (issuer !== undefined) {
            return {
                sessionId,
                webId,
                isLoggedIn: isLoggedIn === "true",
                refreshToken,
                issuer,
            };
        }
        return undefined;
    }
    async clear(sessionId) {
        const rawSessions = await this.storageUtility.get(KEY_REGISTERED_SESSIONS);
        if (rawSessions !== undefined) {
            const sessions = JSON.parse(rawSessions);
            await this.storageUtility.set(KEY_REGISTERED_SESSIONS, JSON.stringify(sessions.filter((storedSessionId) => storedSessionId !== sessionId)));
        }
        return super.clear(sessionId);
    }
    async register(sessionId) {
        const rawSessions = await this.storageUtility.get(KEY_REGISTERED_SESSIONS);
        if (rawSessions === undefined) {
            return this.storageUtility.set(KEY_REGISTERED_SESSIONS, JSON.stringify([sessionId]));
        }
        const sessions = JSON.parse(rawSessions);
        if (!sessions.includes(sessionId)) {
            sessions.push(sessionId);
            return this.storageUtility.set(KEY_REGISTERED_SESSIONS, JSON.stringify(sessions));
        }
        return Promise.resolve();
    }
    async getRegisteredSessionIdAll() {
        return this.storageUtility.get(KEY_REGISTERED_SESSIONS).then((data) => {
            if (data === undefined) {
                return [];
            }
            return JSON.parse(data);
        });
    }
    async clearAll() {
        const rawSessions = await this.storageUtility.get(KEY_REGISTERED_SESSIONS);
        if (rawSessions === undefined) {
            return Promise.resolve();
        }
        const sessions = JSON.parse(rawSessions);
        await Promise.all(sessions.map((sessionId) => this.clear(sessionId)));
        return this.storageUtility.set(KEY_REGISTERED_SESSIONS, JSON.stringify([]));
    }
}

class AuthCodeRedirectHandler {
    constructor(storageUtility, sessionInfoManager, issuerConfigFetcher, clientRegistrar, tokenRefresher) {
        this.storageUtility = storageUtility;
        this.sessionInfoManager = sessionInfoManager;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.clientRegistrar = clientRegistrar;
        this.tokenRefresher = tokenRefresher;
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
    async handle(inputRedirectUrl, eventEmitter) {
        if (!(await this.canHandle(inputRedirectUrl))) {
            throw new Error(`AuthCodeRedirectHandler cannot handle [${inputRedirectUrl}]: it is missing one of [code, state].`);
        }
        const url = new URL(inputRedirectUrl);
        const oauthState = url.searchParams.get("state");
        url.searchParams.delete("code");
        url.searchParams.delete("state");
        const sessionId = await getSessionIdFromOauthState(this.storageUtility, oauthState);
        if (sessionId === undefined) {
            throw new Error(`No stored session is associated with the state [${oauthState}]`);
        }
        const oidcContext = await loadOidcContextFromStorage(sessionId, this.storageUtility, this.issuerConfigFetcher);
        const issuer = new Issuer(configToIssuerMetadata(oidcContext.issuerConfig));
        const clientInfo = await this.clientRegistrar.getClient({ sessionId }, oidcContext.issuerConfig);
        const client = new issuer.Client({
            client_id: clientInfo.clientId,
            client_secret: clientInfo.clientSecret,
            token_endpoint_auth_method: clientInfo.clientSecret
                ? "client_secret_basic"
                : "none",
            id_token_signed_response_alg: clientInfo.idTokenSignedResponseAlg,
        });
        const params = client.callbackParams(inputRedirectUrl);
        let dpopKey;
        if (oidcContext.dpop) {
            dpopKey = await generateDpopKeyPair();
        }
        const tokenSet = await client.callback(url.href, params, { code_verifier: oidcContext.codeVerifier, state: oauthState }, { DPoP: dpopKey === null || dpopKey === void 0 ? void 0 : dpopKey.privateKey });
        const iss = url.searchParams.get("iss");
        if (typeof iss === "string" && iss !== oidcContext.issuerConfig.issuer) {
            throw new Error(`The value of the iss parameter (${iss}) does not match the issuer identifier of the authorization server (${oidcContext.issuerConfig.issuer}). See [rfc9207](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.3-3.1.1)`);
        }
        if (tokenSet.access_token === undefined ||
            tokenSet.id_token === undefined) {
            throw new Error(`The Identity Provider [${issuer.metadata.issuer}] did not return the expected tokens: missing at least one of 'access_token', 'id_token.`);
        }
        let refreshOptions;
        if (tokenSet.refresh_token !== undefined) {
            eventEmitter === null || eventEmitter === void 0 ? void 0 : eventEmitter.emit(EVENTS.NEW_REFRESH_TOKEN, tokenSet.refresh_token);
            refreshOptions = {
                refreshToken: tokenSet.refresh_token,
                sessionId,
                tokenRefresher: this.tokenRefresher,
            };
        }
        const authFetch = await buildAuthenticatedFetch(fetch, tokenSet.access_token, {
            dpopKey,
            refreshOptions,
            eventEmitter,
            expiresIn: tokenSet.expires_in,
        });
        const webid = await getWebidFromTokenPayload(tokenSet.id_token, issuer.metadata.jwks_uri, issuer.metadata.issuer, client.metadata.client_id);
        await saveSessionInfoToStorage(this.storageUtility, sessionId, webid, "true", tokenSet.refresh_token, undefined, dpopKey);
        const sessionInfo = await this.sessionInfoManager.get(sessionId);
        if (!sessionInfo) {
            throw new Error(`Could not find any session information associated with SessionID [${sessionId}] in our storage.`);
        }
        return Object.assign(sessionInfo, {
            fetch: authFetch,
            expirationDate: typeof tokenSet.expires_in === "number"
                ? tokenSet.expires_in * 1000 + Date.now()
                : undefined,
            getLogoutUrl: maybeBuildRpInitiatedLogout({
                idTokenHint: tokenSet.id_token,
                endSessionEndpoint: oidcContext.issuerConfig.endSessionEndpoint,
            }),
        });
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
        return getUnauthenticatedSession();
    }
}

class AggregateIncomingRedirectHandler extends AggregateHandler {
    constructor(redirectHandlers) {
        super(redirectHandlers);
    }
}

class Redirector {
    redirect(redirectUrl, options) {
        if (options && options.handleRedirect) {
            options.handleRedirect(redirectUrl);
        }
        else {
            throw new Error("A redirection handler must be provided in the Node environment.");
        }
    }
}

function negotiateClientSigningAlg(issuerConfig, clientPreference) {
    if (!Array.isArray(issuerConfig.idTokenSigningAlgValuesSupported)) {
        throw new Error("The OIDC issuer discovery profile is missing the 'id_token_signing_alg_values_supported' value, which is mandatory.");
    }
    const signingAlg = determineSigningAlg(issuerConfig.idTokenSigningAlgValuesSupported, clientPreference);
    if (signingAlg === null) {
        throw new Error(`No signature algorithm match between ${JSON.stringify(issuerConfig.idTokenSigningAlgValuesSupported)} supported by the Identity Provider and ${JSON.stringify(clientPreference)} preferred by the client.`);
    }
    return signingAlg;
}
class ClientRegistrar {
    constructor(storageUtility) {
        this.storageUtility = storageUtility;
    }
    async getClient(options, issuerConfig) {
        var _a, _b;
        const [storedClientId, storedClientSecret, storedClientName, storedIdTokenSignedResponseAlg,] = await Promise.all([
            this.storageUtility.getForUser(options.sessionId, "clientId"),
            this.storageUtility.getForUser(options.sessionId, "clientSecret"),
            this.storageUtility.getForUser(options.sessionId, "clientName"),
            this.storageUtility.getForUser(options.sessionId, "idTokenSignedResponseAlg"),
        ]);
        if (storedClientId) {
            return {
                clientId: storedClientId,
                clientSecret: storedClientSecret,
                clientName: storedClientName,
                idTokenSignedResponseAlg: storedIdTokenSignedResponseAlg !== null && storedIdTokenSignedResponseAlg !== void 0 ? storedIdTokenSignedResponseAlg : negotiateClientSigningAlg(issuerConfig, PREFERRED_SIGNING_ALG),
                clientType: "dynamic",
            };
        }
        const issuer = new Issuer(configToIssuerMetadata(issuerConfig));
        if (issuer.metadata.registration_endpoint === undefined) {
            throw new ConfigurationError(`Dynamic client registration cannot be performed, because issuer does not have a registration endpoint: ${JSON.stringify(issuer.metadata)}`);
        }
        const signingAlg = negotiateClientSigningAlg(issuerConfig, PREFERRED_SIGNING_ALG);
        const registeredClient = await issuer.Client.register({
            redirect_uris: [options.redirectUrl],
            client_name: options.clientName,
            id_token_signed_response_alg: signingAlg,
            grant_types: ["authorization_code", "refresh_token"],
        });
        const infoToSave = {
            clientId: registeredClient.metadata.client_id,
            idTokenSignedResponseAlg: (_a = registeredClient.metadata.id_token_signed_response_alg) !== null && _a !== void 0 ? _a : signingAlg,
        };
        if (registeredClient.metadata.client_secret) {
            infoToSave.clientSecret = registeredClient.metadata.client_secret;
        }
        await this.storageUtility.setForUser(options.sessionId, infoToSave);
        return {
            clientId: registeredClient.metadata.client_id,
            clientSecret: registeredClient.metadata.client_secret,
            clientName: registeredClient.metadata.client_name,
            idTokenSignedResponseAlg: (_b = registeredClient.metadata.id_token_signed_response_alg) !== null && _b !== void 0 ? _b : signingAlg,
            clientType: "dynamic",
        };
    }
}

const tokenSetToTokenEndpointResponse = (tokenSet, issuerMetadata) => {
    if (tokenSet.access_token === undefined) {
        throw new Error(`The Identity Provider [${issuerMetadata.issuer}] did not return an access token on refresh.`);
    }
    if (tokenSet.token_type !== "Bearer" && tokenSet.token_type !== "DPoP") {
        throw new Error(`The Identity Provider [${issuerMetadata.issuer}] returned an unknown token type: [${tokenSet.token_type}].`);
    }
    return {
        accessToken: tokenSet.access_token,
        tokenType: tokenSet.token_type,
        idToken: tokenSet.id_token,
        refreshToken: tokenSet.refresh_token,
        expiresAt: tokenSet.expires_at,
    };
};
class TokenRefresher {
    constructor(storageUtility, issuerConfigFetcher, clientRegistrar) {
        this.storageUtility = storageUtility;
        this.issuerConfigFetcher = issuerConfigFetcher;
        this.clientRegistrar = clientRegistrar;
    }
    async refresh(sessionId, refreshToken, dpopKey, eventEmitter) {
        const oidcContext = await loadOidcContextFromStorage(sessionId, this.storageUtility, this.issuerConfigFetcher);
        const issuer = new Issuer(configToIssuerMetadata(oidcContext.issuerConfig));
        const clientInfo = await this.clientRegistrar.getClient({ sessionId }, oidcContext.issuerConfig);
        if (clientInfo.idTokenSignedResponseAlg === undefined) {
            clientInfo.idTokenSignedResponseAlg = negotiateClientSigningAlg(oidcContext.issuerConfig, PREFERRED_SIGNING_ALG);
        }
        const client = new issuer.Client({
            client_id: clientInfo.clientId,
            client_secret: clientInfo.clientSecret,
            token_endpoint_auth_method: clientInfo.clientSecret
                ? "client_secret_basic"
                : "none",
            id_token_signed_response_alg: clientInfo.idTokenSignedResponseAlg,
        });
        if (refreshToken === undefined) {
            throw new Error(`Session [${sessionId}] has no refresh token to allow it to refresh its access token.`);
        }
        if (oidcContext.dpop && dpopKey === undefined) {
            throw new Error(`For session [${sessionId}], the key bound to the DPoP access token must be provided to refresh said access token.`);
        }
        const tokenSet = tokenSetToTokenEndpointResponse(await client.refresh(refreshToken, {
            DPoP: dpopKey ? dpopKey.privateKey : undefined,
        }), issuer.metadata);
        if (tokenSet.refreshToken !== undefined) {
            eventEmitter === null || eventEmitter === void 0 ? void 0 : eventEmitter.emit(EVENTS.NEW_REFRESH_TOKEN, tokenSet.refreshToken);
            await this.storageUtility.setForUser(sessionId, {
                refreshToken: tokenSet.refreshToken,
            });
        }
        return tokenSet;
    }
}

class ClientCredentialsOidcHandler {
    constructor(tokenRefresher, _storageUtility) {
        this.tokenRefresher = tokenRefresher;
        this._storageUtility = _storageUtility;
    }
    async canHandle(oidcLoginOptions) {
        return (typeof oidcLoginOptions.client.clientId === "string" &&
            typeof oidcLoginOptions.client.clientSecret === "string" &&
            oidcLoginOptions.client.clientType === "static");
    }
    async handle(oidcLoginOptions) {
        const issuer = new Issuer(configToIssuerMetadata(oidcLoginOptions.issuerConfiguration));
        const client = new issuer.Client({
            client_id: oidcLoginOptions.client.clientId,
            client_secret: oidcLoginOptions.client.clientSecret,
        });
        let dpopKey;
        if (oidcLoginOptions.dpop) {
            dpopKey = await generateDpopKeyPair();
            [dpopKey.publicKey.alg] = PREFERRED_SIGNING_ALG;
        }
        const tokens = await client.grant({
            grant_type: "client_credentials",
            token_endpoint_auth_method: "client_secret_basic",
            scope: DEFAULT_SCOPES,
        }, {
            DPoP: oidcLoginOptions.dpop && dpopKey !== undefined
                ? dpopKey.privateKey
                : undefined,
        });
        let webId;
        if (tokens.access_token === undefined) {
            throw new Error(`Invalid response from Solid Identity Provider [${oidcLoginOptions.issuer}]: ${JSON.stringify(tokens)} is missing 'access_token'.`);
        }
        if (tokens.id_token === undefined) {
            webId = await getWebidFromTokenPayload(tokens.access_token, oidcLoginOptions.issuerConfiguration.jwksUri, oidcLoginOptions.issuer, "solid");
        }
        else {
            webId = await getWebidFromTokenPayload(tokens.id_token, oidcLoginOptions.issuerConfiguration.jwksUri, oidcLoginOptions.issuer, oidcLoginOptions.client.clientId);
        }
        const authFetch = await buildAuthenticatedFetch(fetch, tokens.access_token, {
            dpopKey,
            refreshOptions: tokens.refresh_token
                ? {
                    refreshToken: tokens.refresh_token,
                    sessionId: oidcLoginOptions.sessionId,
                    tokenRefresher: this.tokenRefresher,
                }
                : undefined,
            eventEmitter: oidcLoginOptions.eventEmitter,
            expiresIn: tokens.expires_in,
        });
        const sessionInfo = {
            isLoggedIn: true,
            sessionId: oidcLoginOptions.sessionId,
            webId,
            expirationDate: tokens.expires_in !== undefined
                ? Date.now() + tokens.expires_in * 1000
                : undefined,
        };
        return Object.assign(sessionInfo, {
            fetch: authFetch,
        });
    }
}

const buildLoginHandler = (storageUtility, tokenRefresher, issuerConfigFetcher, clientRegistrar) => {
    return new OidcLoginHandler(storageUtility, new AggregateOidcHandler([
        new RefreshTokenOidcHandler(tokenRefresher, storageUtility),
        new ClientCredentialsOidcHandler(tokenRefresher, storageUtility),
        new AuthorizationCodeWithPkceOidcHandler(storageUtility, new Redirector()),
    ]), issuerConfigFetcher, clientRegistrar);
};
const buildRedirectHandler = (storageUtility, sessionInfoManager, issuerConfigFetcher, clientRegistrar, tokenRefresher) => {
    return new AggregateIncomingRedirectHandler([
        new AuthCodeRedirectHandler(storageUtility, sessionInfoManager, issuerConfigFetcher, clientRegistrar, tokenRefresher),
        new FallbackRedirectHandler(),
    ]);
};
function getClientAuthenticationWithDependencies(dependencies) {
    const inMemoryStorage = new InMemoryStorage();
    const secureStorage = dependencies.secureStorage || inMemoryStorage;
    const insecureStorage = dependencies.insecureStorage || inMemoryStorage;
    const storageUtility = new StorageUtilityNode(secureStorage, insecureStorage);
    const issuerConfigFetcher = new IssuerConfigFetcher(storageUtility);
    const clientRegistrar = new ClientRegistrar(storageUtility);
    const sessionInfoManager = new SessionInfoManager(storageUtility);
    const tokenRefresher = new TokenRefresher(storageUtility, issuerConfigFetcher, clientRegistrar);
    const loginHandler = buildLoginHandler(storageUtility, tokenRefresher, issuerConfigFetcher, clientRegistrar);
    const redirectHandler = buildRedirectHandler(storageUtility, sessionInfoManager, issuerConfigFetcher, clientRegistrar, tokenRefresher);
    return new ClientAuthentication(loginHandler, redirectHandler, new IWaterfallLogoutHandler(sessionInfoManager, new Redirector()), sessionInfoManager);
}

const defaultStorage = new InMemoryStorage();
class Session extends EventEmitter {
    constructor(sessionOptions = {}, sessionId = undefined) {
        super();
        this.tokenRequestInProgress = false;
        this.lastTimeoutHandle = 0;
        this.login = async (options) => {
            const loginInfo = await this.clientAuthentication.login(this.info.sessionId, {
                ...options,
            }, this.events);
            if (loginInfo !== undefined) {
                this.info.isLoggedIn = loginInfo.isLoggedIn;
                this.info.sessionId = loginInfo.sessionId;
                this.info.webId = loginInfo.webId;
                this.info.expirationDate = loginInfo.expirationDate;
            }
            if (loginInfo === null || loginInfo === void 0 ? void 0 : loginInfo.isLoggedIn) {
                this.events.emit(EVENTS.LOGIN);
            }
        };
        this.fetch = async (url, init) => {
            if (!this.info.isLoggedIn) {
                return fetch(url, init);
            }
            return this.clientAuthentication.fetch(url, init);
        };
        this.logout = async (options) => this.internalLogout(true, options);
        this.internalLogout = async (emitEvent, options) => {
            await this.clientAuthentication.logout(this.info.sessionId, options);
            clearTimeout(this.lastTimeoutHandle);
            this.info.isLoggedIn = false;
            if (emitEvent) {
                this.events.emit(EVENTS.LOGOUT);
            }
        };
        this.handleIncomingRedirect = async (url) => {
            let sessionInfo;
            if (this.info.isLoggedIn) {
                sessionInfo = this.info;
            }
            else if (this.tokenRequestInProgress) ;
            else {
                try {
                    this.tokenRequestInProgress = true;
                    sessionInfo = await this.clientAuthentication.handleIncomingRedirect(url, this.events);
                    if (sessionInfo) {
                        this.info.isLoggedIn = sessionInfo.isLoggedIn;
                        this.info.webId = sessionInfo.webId;
                        this.info.sessionId = sessionInfo.sessionId;
                        if (sessionInfo.isLoggedIn) {
                            this.events.emit(EVENTS.LOGIN);
                        }
                    }
                }
                finally {
                    this.tokenRequestInProgress = false;
                }
            }
            return sessionInfo;
        };
        this.events = new Proxy(this, buildProxyHandler(Session.prototype, "events only implements ISessionEventListener"));
        if (sessionOptions.clientAuthentication) {
            this.clientAuthentication = sessionOptions.clientAuthentication;
        }
        else if (sessionOptions.storage) {
            this.clientAuthentication = getClientAuthenticationWithDependencies({
                secureStorage: sessionOptions.storage,
                insecureStorage: sessionOptions.storage,
            });
        }
        else if (sessionOptions.secureStorage && sessionOptions.insecureStorage) {
            this.clientAuthentication = getClientAuthenticationWithDependencies({
                secureStorage: sessionOptions.secureStorage,
                insecureStorage: sessionOptions.insecureStorage,
            });
        }
        else {
            this.clientAuthentication = getClientAuthenticationWithDependencies({
                secureStorage: defaultStorage,
                insecureStorage: defaultStorage,
            });
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
                sessionId: sessionId !== null && sessionId !== void 0 ? sessionId : v4(),
                isLoggedIn: false,
            };
        }
        if (sessionOptions.onNewRefreshToken !== undefined) {
            this.events.on(EVENTS.NEW_REFRESH_TOKEN, sessionOptions.onNewRefreshToken);
        }
        this.events.on(EVENTS.TIMEOUT_SET, (timeoutHandle) => {
            this.lastTimeoutHandle = timeoutHandle;
        });
        this.events.on(EVENTS.ERROR, () => this.internalLogout(false));
        this.events.on(EVENTS.SESSION_EXPIRED, () => this.internalLogout(false));
    }
    onLogin(callback) {
        this.events.on(EVENTS.LOGIN, callback);
    }
    onLogout(callback) {
        this.events.on(EVENTS.LOGOUT, callback);
    }
    onNewRefreshToken(callback) {
        this.events.on(EVENTS.NEW_REFRESH_TOKEN, callback);
    }
}

async function getSessionFromStorage(sessionId, storage, onNewRefreshToken) {
    const clientAuth = storage
        ? getClientAuthenticationWithDependencies({
            secureStorage: storage,
            insecureStorage: storage,
        })
        : getClientAuthenticationWithDependencies({
            secureStorage: defaultStorage,
            insecureStorage: defaultStorage,
        });
    const sessionInfo = await clientAuth.getSessionInfo(sessionId);
    if (sessionInfo === undefined) {
        return undefined;
    }
    const session = new Session({
        sessionInfo,
        clientAuthentication: clientAuth,
        onNewRefreshToken,
    });
    if (sessionInfo.refreshToken) {
        await session.login({
            oidcIssuer: sessionInfo.issuer,
        });
    }
    return session;
}
async function getSessionIdFromStorageAll(storage) {
    const clientAuth = storage
        ? getClientAuthenticationWithDependencies({
            secureStorage: storage,
            insecureStorage: storage,
        })
        : getClientAuthenticationWithDependencies({
            secureStorage: defaultStorage,
            insecureStorage: defaultStorage,
        });
    return clientAuth.getSessionIdAll();
}
async function clearSessionFromStorageAll(storage) {
    const clientAuth = storage
        ? getClientAuthenticationWithDependencies({
            secureStorage: storage,
            insecureStorage: storage,
        })
        : getClientAuthenticationWithDependencies({
            secureStorage: defaultStorage,
            insecureStorage: defaultStorage,
        });
    return clientAuth.clearSessionAll();
}

export { Session, clearSessionFromStorageAll, getSessionFromStorage, getSessionIdFromStorageAll };
//# sourceMappingURL=index.mjs.map
