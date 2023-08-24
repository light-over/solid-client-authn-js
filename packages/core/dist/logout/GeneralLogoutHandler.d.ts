import type ILogoutHandler from "./ILogoutHandler";
import type { ISessionInfoManager } from "../sessionInfo/ISessionInfoManager";
export default class GeneralLogoutHandler implements ILogoutHandler {
    private sessionInfoManager;
    constructor(sessionInfoManager: ISessionInfoManager);
    canHandle(): Promise<boolean>;
    handle(userId: string): Promise<void>;
}
