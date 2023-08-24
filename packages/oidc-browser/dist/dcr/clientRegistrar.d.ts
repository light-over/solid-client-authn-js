import type { IIssuerConfig, IClient, IClientRegistrarOptions } from "@inrupt/solid-client-authn-core";
export declare function registerClient(options: IClientRegistrarOptions, issuerConfig: IIssuerConfig): Promise<IClient>;
