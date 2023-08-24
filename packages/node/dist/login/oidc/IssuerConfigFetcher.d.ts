import type { IIssuerConfig, IIssuerConfigFetcher, IStorageUtility } from "@inrupt/solid-client-authn-core";
import type { IssuerMetadata } from "openid-client";
export declare function configFromIssuerMetadata(metadata: IssuerMetadata): IIssuerConfig;
export declare function configToIssuerMetadata(config: IIssuerConfig): IssuerMetadata;
export default class IssuerConfigFetcher implements IIssuerConfigFetcher {
    private storageUtility;
    constructor(storageUtility: IStorageUtility);
    static getLocalStorageKey(issuer: string): string;
    fetchConfig(issuer: string): Promise<IIssuerConfig>;
}
