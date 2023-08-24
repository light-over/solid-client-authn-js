import type { IClientRegistrar, IStorageUtility, IIssuerConfigFetcher } from "@inrupt/solid-client-authn-core";
export interface ITokenRequester {
    request(localUserId: string, body: Record<string, string>): Promise<void>;
}
export default class TokenRequester {
    private storageUtility;
    private issuerConfigFetcher;
    private clientRegistrar;
    constructor(storageUtility: IStorageUtility, issuerConfigFetcher: IIssuerConfigFetcher, clientRegistrar: IClientRegistrar);
    request(_sessionId: string, _body: Record<string, string>): Promise<void>;
}
