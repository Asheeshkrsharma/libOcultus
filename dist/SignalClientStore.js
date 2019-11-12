"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const Converters = __importStar(require("./Converter"));
const Database_1 = require("./Database");
const path_1 = __importDefault(require("path"));
const libsignal = require('libsignal');
const SessionRecord = libsignal.SessionRecord;
const privates = new WeakMap();
class SignalClientStore {
    constructor(userId, password, dBPath) {
        this.store = {};
        this.userId = userId;
        dBPath = `${path_1.default.resolve(dBPath)}/`;
        privates.set(this, {
            _database: new Database_1.ClientStoreDataBase(this.userId, password, dBPath)
        });
        this.store = new Proxy(this.store, {
            deleteProperty: (target, property) => {
                if (property === null || property === undefined) {
                    throw new Error('Tried to remove value for undefined/null key');
                    return false;
                }
                privates.get(this)._database.remove(property);
                delete target[property];
                return true;
            },
            set: (target, property, value) => {
                if (property === undefined || value === undefined
                    || property === null || value === null) {
                    throw new Error('Tried to store undefined/null');
                }
                target[property] = value;
                privates.get(this)._database.set(property, value);
                return true;
            },
            get: (target, property) => {
                let value;
                if (property === null || property === undefined) {
                    throw new Error('Tried to get value for undefined/null key');
                }
                if (property in target) {
                    value = target[property];
                }
                else {
                    value = privates.get(this)._database.get(property);
                    if (target[property] !== value) {
                        target[property] = value;
                    }
                }
                return value;
            }
        });
    }
    remove(key) {
        delete this.store[key];
    }
    get(key) {
        return this.store[key];
    }
    put(key, value) {
        this.store[key] = value;
    }
    getIdentityKeyPair() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield Promise.resolve(this.store['identityKey']);
        });
    }
    isTrustedIdentity(protocolAddressIdentifier, identityKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (protocolAddressIdentifier === null ||
                protocolAddressIdentifier === undefined) {
                throw new Error('Tried to check identity key for undefined/null key');
            }
            if (!(identityKey instanceof Buffer)) {
                throw new Error('Expected identityKey to be a Buffer');
            }
            const trusted = yield this.store['identityKey' + protocolAddressIdentifier];
            if (trusted === undefined) {
                return Promise.resolve(true);
            }
            return yield Promise.resolve(Converters.toString(identityKey)
                === Converters.toString(trusted));
        });
    }
    getOurRegistrationId() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield Promise.resolve(this.store['registrationId']);
        });
    }
    getOurIdentity() {
        return __awaiter(this, void 0, void 0, function* () {
            let res = yield this.store['identityKey'];
            if (res !== undefined) {
                if (res.pubKey.type === 'Buffer') {
                    res = {
                        pubKey: Buffer.from(res.pubKey.data),
                        privKey: Buffer.from(res.privKey.data)
                    };
                }
            }
            return Promise.resolve(res);
        });
    }
    loadIdentityKey(protocolAddressIdentifier) {
        return __awaiter(this, void 0, void 0, function* () {
            if (protocolAddressIdentifier === null
                || protocolAddressIdentifier === undefined) {
                throw new Error('Tried to get identity key for undefined/null key');
            }
            return yield Promise.resolve(this.store['identityKey' + protocolAddressIdentifier]);
        });
    }
    saveIdentity(protocolAddressIdentifier, identityKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (protocolAddressIdentifier === null ||
                protocolAddressIdentifier === undefined) {
                throw new Error('Tried to put identity key for undefined/null key');
            }
            const address = new libsignal.SignalProtocolAddress.fromString(protocolAddressIdentifier);
            const existing = this.store['identityKey' + address.getName()];
            this.store['identityKey' + address.getName()] = identityKey;
            if (existing && Converters.toString(identityKey) !==
                Converters.toString(existing)) {
                return yield Promise.resolve(true);
            }
            else {
                return yield Promise.resolve(false);
            }
        });
    }
    loadPreKey(preKeyIdentity) {
        return __awaiter(this, void 0, void 0, function* () {
            let res = yield this.store['25519KeypreKey' + preKeyIdentity];
            if (res !== undefined) {
                if (res.pubKey.type === 'Buffer') {
                    res = {
                        pubKey: Buffer.from(res.pubKey.data),
                        privKey: Buffer.from(res.privKey.data)
                    };
                }
            }
            return Promise.resolve(res);
        });
    }
    storePreKey(keyId, keyPair) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield Promise.resolve(this.store['25519KeypreKey' + keyId] = keyPair);
        });
    }
    removePreKey(keyId) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield Promise.resolve(delete this.store['25519KeypreKey' + keyId]);
        });
    }
    loadSignedPreKey(preKeyIdentity) {
        return __awaiter(this, void 0, void 0, function* () {
            let res = yield this.store['25519KeysignedKey' + preKeyIdentity];
            if (res !== undefined) {
                if (res.pubKey.type === 'Buffer') {
                    res = {
                        pubKey: Buffer.from(res.pubKey.data),
                        privKey: Buffer.from(res.privKey.data)
                    };
                }
            }
            return Promise.resolve(res);
        });
    }
    storeSignedPreKey(keyId, signedKeyPair) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield Promise.resolve(this.store['25519KeysignedKey' + keyId] = signedKeyPair);
        });
    }
    removeSignedPreKey(keyId) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield Promise.resolve(delete this.store['25519KeysignedKey' + keyId]);
        });
    }
    loadSession(identifier) {
        return __awaiter(this, void 0, void 0, function* () {
            const sessionRecordJson = yield this.store['session' + identifier];
            return Promise.resolve(sessionRecordJson
                !== undefined ? SessionRecord.deserialize(sessionRecordJson) : undefined);
        });
    }
    storeSession(protocolAddressIdentifier, record) {
        return __awaiter(this, void 0, void 0, function* () {
            const serialized = yield record.serialize();
            this.store['session' + protocolAddressIdentifier] = serialized;
        });
    }
    removeSession(protocolAddressIdentifier) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield Promise.resolve(delete this.store['session' + protocolAddressIdentifier]);
        });
    }
    removeAllSessions(protocolAddressIdentifier) {
        return __awaiter(this, void 0, void 0, function* () {
            for (const id in this.store) {
                if (id.startsWith('session' + protocolAddressIdentifier)) {
                    delete this.store[id];
                }
            }
            return yield Promise.resolve();
        });
    }
}
exports.SignalClientStore = SignalClientStore;
//# sourceMappingURL=SignalClientStore.js.map