import { ClientAuthentication as ClientAuthenticationBase } from "@inrupt/solid-client-authn-core";
import type { ILoginInputOptions, ISessionInfo } from "@inrupt/solid-client-authn-core";
import type { EventEmitter } from "events";
export default class ClientAuthentication extends ClientAuthenticationBase {
    login: (sessionId: string, options: ILoginInputOptions, eventEmitter: EventEmitter) => Promise<ISessionInfo | undefined>;
    getSessionIdAll: () => Promise<string[]>;
    registerSession: (sessionId: string) => Promise<void>;
    clearSessionAll: () => Promise<void>;
    handleIncomingRedirect: (url: string, eventEmitter: EventEmitter) => Promise<ISessionInfo | undefined>;
}
