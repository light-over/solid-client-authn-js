import type { IStorage, ITokenRefresher, IIssuerConfigFetcher, IClientRegistrar, IStorageUtility, ILoginHandler, ISessionInfoManager, IIncomingRedirectHandler } from "@inrupt/solid-client-authn-core";
import ClientAuthentication from "./ClientAuthentication";
export declare const buildLoginHandler: (storageUtility: IStorageUtility, tokenRefresher: ITokenRefresher, issuerConfigFetcher: IIssuerConfigFetcher, clientRegistrar: IClientRegistrar) => ILoginHandler;
export declare const buildRedirectHandler: (storageUtility: IStorageUtility, sessionInfoManager: ISessionInfoManager, issuerConfigFetcher: IIssuerConfigFetcher, clientRegistrar: IClientRegistrar, tokenRefresher: ITokenRefresher) => IIncomingRedirectHandler;
export declare function getClientAuthenticationWithDependencies(dependencies: {
    secureStorage?: IStorage;
    insecureStorage?: IStorage;
}): ClientAuthentication;
