import type { IStorage } from "@inrupt/solid-client-authn-core";
import { Session } from "./Session";
export declare function getSessionFromStorage(sessionId: string, storage?: IStorage, onNewRefreshToken?: (newToken: string) => unknown): Promise<Session | undefined>;
export declare function getSessionIdFromStorageAll(storage?: IStorage): Promise<string[]>;
export declare function clearSessionFromStorageAll(storage?: IStorage): Promise<void>;
