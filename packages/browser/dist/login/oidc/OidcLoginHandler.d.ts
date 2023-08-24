import type { IClientRegistrar, IIssuerConfigFetcher, ILoginOptions, ILoginHandler, IOidcHandler, IStorageUtility, LoginResult } from "@inrupt/solid-client-authn-core";
export default class OidcLoginHandler implements ILoginHandler {
    private storageUtility;
    private oidcHandler;
    private issuerConfigFetcher;
    private clientRegistrar;
    constructor(storageUtility: IStorageUtility, oidcHandler: IOidcHandler, issuerConfigFetcher: IIssuerConfigFetcher, clientRegistrar: IClientRegistrar);
    canHandle(options: ILoginOptions): Promise<boolean>;
    handle(options: ILoginOptions): Promise<LoginResult>;
}
