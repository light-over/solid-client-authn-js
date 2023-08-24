import type { ISessionInfo, ISessionInternalInfo, ISessionInfoManager } from "@inrupt/solid-client-authn-core";
import { SessionInfoManagerBase } from "@inrupt/solid-client-authn-core";
export { getUnauthenticatedSession, clear, } from "@inrupt/solid-client-authn-core";
export declare class SessionInfoManager extends SessionInfoManagerBase implements ISessionInfoManager {
    get(sessionId: string): Promise<(ISessionInfo & ISessionInternalInfo) | undefined>;
    clear(sessionId: string): Promise<void>;
    register(sessionId: string): Promise<void>;
    getRegisteredSessionIdAll(): Promise<string[]>;
    clearAll(): Promise<void>;
}
