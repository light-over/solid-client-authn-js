import type { IStorage } from "@inrupt/solid-client-authn-core";
import { StorageUtility } from "@inrupt/solid-client-authn-core";
export default class StorageUtilityNode extends StorageUtility {
    constructor(secureStorage: IStorage, insecureStorage: IStorage);
}
