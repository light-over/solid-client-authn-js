import 'jose';
import { jest } from '@jest/globals';
import 'uuid';
import '@inrupt/universal-fetch';

class StorageUtility {
    constructor(secureStorage, insecureStorage) {
        this.secureStorage = secureStorage;
        this.insecureStorage = insecureStorage;
    }
    getKey(userId) {
        return `solidClientAuthenticationUser:${userId}`;
    }
    async getUserData(userId, secure) {
        const stored = await (secure
            ? this.secureStorage
            : this.insecureStorage).get(this.getKey(userId));
        if (stored === undefined) {
            return {};
        }
        try {
            return JSON.parse(stored);
        }
        catch (err) {
            throw new Error(`Data for user [${userId}] in [${secure ? "secure" : "unsecure"}] storage is corrupted - expected valid JSON, but got: ${stored}`);
        }
    }
    async setUserData(userId, data, secure) {
        await (secure ? this.secureStorage : this.insecureStorage).set(this.getKey(userId), JSON.stringify(data));
    }
    async get(key, options) {
        const value = await ((options === null || options === void 0 ? void 0 : options.secure)
            ? this.secureStorage
            : this.insecureStorage).get(key);
        if (value === undefined && (options === null || options === void 0 ? void 0 : options.errorIfNull)) {
            throw new Error(`[${key}] is not stored`);
        }
        return value;
    }
    async set(key, value, options) {
        return ((options === null || options === void 0 ? void 0 : options.secure) ? this.secureStorage : this.insecureStorage).set(key, value);
    }
    async delete(key, options) {
        return ((options === null || options === void 0 ? void 0 : options.secure) ? this.secureStorage : this.insecureStorage).delete(key);
    }
    async getForUser(userId, key, options) {
        const userData = await this.getUserData(userId, options === null || options === void 0 ? void 0 : options.secure);
        let value;
        if (!userData || !userData[key]) {
            value = undefined;
        }
        value = userData[key];
        if (value === undefined && (options === null || options === void 0 ? void 0 : options.errorIfNull)) {
            throw new Error(`Field [${key}] for user [${userId}] is not stored`);
        }
        return value || undefined;
    }
    async setForUser(userId, values, options) {
        let userData;
        try {
            userData = await this.getUserData(userId, options === null || options === void 0 ? void 0 : options.secure);
        }
        catch (_a) {
            userData = {};
        }
        await this.setUserData(userId, { ...userData, ...values }, options === null || options === void 0 ? void 0 : options.secure);
    }
    async deleteForUser(userId, key, options) {
        const userData = await this.getUserData(userId, options === null || options === void 0 ? void 0 : options.secure);
        delete userData[key];
        await this.setUserData(userId, userData, options === null || options === void 0 ? void 0 : options.secure);
    }
    async deleteAllUserData(userId, options) {
        await ((options === null || options === void 0 ? void 0 : options.secure) ? this.secureStorage : this.insecureStorage).delete(this.getKey(userId));
    }
}

const StorageUtilityGetResponse = "getResponse";
const StorageUtilityMock = {
    get: async (key, options) => StorageUtilityGetResponse,
    set: async (key, value) => {
    },
    delete: async (key) => {
    },
    getForUser: async (userId, key, options) => StorageUtilityGetResponse,
    setForUser: async (userId, values, options) => {
    },
    deleteForUser: async (userId, key, options) => {
    },
    deleteAllUserData: async (userId, options) => {
    },
};
const mockStorage = (stored) => {
    const store = stored;
    return {
        get: async (key) => {
            if (store[key] === undefined) {
                return undefined;
            }
            if (typeof store[key] === "string") {
                return store[key];
            }
            return JSON.stringify(store[key]);
        },
        set: async (key, value) => {
            store[key] = value;
        },
        delete: async (key) => {
            delete store[key];
        },
    };
};
const mockStorageUtility = (stored, isSecure = false) => {
    if (isSecure) {
        return new StorageUtility(mockStorage(stored), mockStorage({}));
    }
    return new StorageUtility(mockStorage({}), mockStorage(stored));
};

const canHandle = jest.fn((_url) => Promise.resolve(true));
const handle = jest.fn((_url, _emitter) => Promise.resolve({
    sessionId: "global",
    isLoggedIn: true,
    webId: "https://pod.com/profile/card#me",
    fetch: jest.fn(globalThis.fetch),
}));
const mockCanHandleIncomingRedirect = canHandle;
const mockHandleIncomingRedirect = handle;
const mockIncomingRedirectHandler = () => {
    return {
        canHandle,
        handle,
    };
};

async function clear(sessionId, storage) {
    await Promise.all([
        storage.deleteAllUserData(sessionId, { secure: false }),
        storage.deleteAllUserData(sessionId, { secure: true }),
    ]);
}

const mockLogoutHandler = (storageUtility) => {
    return {
        canHandle: jest.fn(async (_localUserId) => Promise.resolve(true)),
        handle: jest.fn(async (localUserId) => {
            return clear(localUserId, storageUtility);
        }),
    };
};

export { StorageUtilityGetResponse, StorageUtilityMock, mockCanHandleIncomingRedirect, mockHandleIncomingRedirect, mockIncomingRedirectHandler, mockLogoutHandler, mockStorage, mockStorageUtility };
