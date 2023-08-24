/// <reference types="node" />
import type { ILoginInputOptions, ISessionInfo, IStorage, ISessionEventListener, IHasSessionEventListener, ILogoutOptions } from "@inrupt/solid-client-authn-core";
import { InMemoryStorage } from "@inrupt/solid-client-authn-core";
import { fetch } from "@inrupt/universal-fetch";
import EventEmitter from "events";
import type ClientAuthentication from "./ClientAuthentication";
export interface ISessionOptions {
    secureStorage: IStorage;
    insecureStorage: IStorage;
    storage: IStorage;
    sessionInfo: ISessionInfo;
    clientAuthentication: ClientAuthentication;
    onNewRefreshToken?: (newToken: string) => unknown;
}
export declare const defaultStorage: InMemoryStorage;
export declare class Session extends EventEmitter implements IHasSessionEventListener {
    readonly info: ISessionInfo;
    readonly events: ISessionEventListener;
    private clientAuthentication;
    private tokenRequestInProgress;
    private lastTimeoutHandle;
    constructor(sessionOptions?: Partial<ISessionOptions>, sessionId?: string | undefined);
    login: (options?: ILoginInputOptions) => Promise<void>;
    fetch: typeof fetch;
    logout: (options?: ILogoutOptions) => Promise<void>;
    private internalLogout;
    handleIncomingRedirect: (url: string) => Promise<ISessionInfo | undefined>;
    onLogin(callback: () => unknown): void;
    onLogout(callback: () => unknown): void;
    onNewRefreshToken(callback: (newToken: string) => unknown): void;
}
