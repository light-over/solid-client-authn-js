import type { IOidcHandler, IOidcOptions, LoginResult, IStorageUtility, ITokenRefresher } from "@inrupt/solid-client-authn-core";
export default class ClientCredentialsOidcHandler implements IOidcHandler {
    private tokenRefresher;
    private _storageUtility;
    constructor(tokenRefresher: ITokenRefresher, _storageUtility: IStorageUtility);
    canHandle(oidcLoginOptions: IOidcOptions): Promise<boolean>;
    handle(oidcLoginOptions: IOidcOptions): Promise<LoginResult>;
}
