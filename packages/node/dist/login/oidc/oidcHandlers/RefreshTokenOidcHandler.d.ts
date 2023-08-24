import type { IOidcHandler, IOidcOptions, IStorageUtility, LoginResult, ITokenRefresher } from "@inrupt/solid-client-authn-core";
export default class RefreshTokenOidcHandler implements IOidcHandler {
    private tokenRefresher;
    private storageUtility;
    constructor(tokenRefresher: ITokenRefresher, storageUtility: IStorageUtility);
    canHandle(oidcLoginOptions: IOidcOptions): Promise<boolean>;
    handle(oidcLoginOptions: IOidcOptions): Promise<LoginResult>;
}
