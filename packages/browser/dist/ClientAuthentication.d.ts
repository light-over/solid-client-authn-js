import type { ISessionInfo, ISessionInternalInfo, ILoginOptions } from "@inrupt/solid-client-authn-core";
import { ClientAuthentication as ClientAuthenticationBase } from "@inrupt/solid-client-authn-core";
import type { EventEmitter } from "events";
export default class ClientAuthentication extends ClientAuthenticationBase {
    login: (options: ILoginOptions, eventEmitter: EventEmitter) => Promise<void>;
    validateCurrentSession: (currentSessionId: string) => Promise<(ISessionInfo & ISessionInternalInfo) | null>;
    handleIncomingRedirect: (url: string, eventEmitter: EventEmitter) => Promise<ISessionInfo | undefined>;
    private cleanUrlAfterRedirect;
}
