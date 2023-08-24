/// <reference types="node" />
import type { IClientRegistrar, IIssuerConfigFetcher, IIncomingRedirectHandler, ISessionInfoManager, IStorageUtility, ITokenRefresher, IncomingRedirectResult } from "@inrupt/solid-client-authn-core";
import type { EventEmitter } from "events";
export declare class AuthCodeRedirectHandler implements IIncomingRedirectHandler {
    private storageUtility;
    private sessionInfoManager;
    private issuerConfigFetcher;
    private clientRegistrar;
    private tokerRefresher;
    constructor(storageUtility: IStorageUtility, sessionInfoManager: ISessionInfoManager, issuerConfigFetcher: IIssuerConfigFetcher, clientRegistrar: IClientRegistrar, tokerRefresher: ITokenRefresher);
    canHandle(redirectUrl: string): Promise<boolean>;
    handle(redirectUrl: string, eventEmitter?: EventEmitter): Promise<IncomingRedirectResult>;
}
