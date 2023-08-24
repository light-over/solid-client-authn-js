import type { IStorageUtility, IClientRegistrar, IIssuerConfig, IClient, IClientRegistrarOptions } from "@inrupt/solid-client-authn-core";
export default class ClientRegistrar implements IClientRegistrar {
    private storageUtility;
    constructor(storageUtility: IStorageUtility);
    getClient(options: IClientRegistrarOptions, issuerConfig: IIssuerConfig): Promise<IClient>;
}
