"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
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
Object.defineProperty(exports, "__esModule", { value: true });
const Converters = __importStar(require("./Converter"));
const Database_1 = require("./Database");
const libsignal = require('libsignal');
const SessionRecord = libsignal.SessionRecord;
const privates = new WeakMap();
class SignalClientStore {
    constructor(userId, password, dBPath) {
        this.store = {};
        this.userId = userId;
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
                    return false;
                }
                target[property] = value;
                privates.get(this)._database.set(property, target[property]);
                return true;
            },
            get: (target, property) => __awaiter(this, void 0, void 0, function* () {
                if (property === null || property === undefined) {
                    throw new Error('Tried to get value for undefined/null key');
                }
                if (property in target) {
                    return target[property];
                }
                else {
                    const value = yield privates.get(this)._database.get(property);
                    if (target[property] !== value) {
                        target[property] = value;
                    }
                }
                return target[property];
            })
        });
    }
    remove(key) {
        return __awaiter(this, void 0, void 0, function* () {
            delete this.store[key];
        });
    }
    get(key) {
        return this.store[key];
    }
    put(key, value) {
        return __awaiter(this, void 0, void 0, function* () {
            this.store[key] = value;
        });
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
            let record;
            if (sessionRecordJson !== undefined) {
                record = SessionRecord.deserialize(sessionRecordJson);
            }
            return Promise.resolve(record);
        });
    }
    storeSession(protocolAddressIdentifier, record) {
        return __awaiter(this, void 0, void 0, function* () {
            const serialized = yield record.serialize();
            return Promise.resolve(this.store['session' + protocolAddressIdentifier] =
                serialized);
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
    storeSessionCipher(protocolAddressIdentifier, cipher) {
        this.store['cipher' + protocolAddressIdentifier]
            = { addr: { id: cipher.addr.id, deviceId: cipher.addr.deviceId } };
    }
    loadSessionCipherAddress(protocolAddressIdentifier) {
        return __awaiter(this, void 0, void 0, function* () {
            const cipher = yield this.store['cipher' + protocolAddressIdentifier];
            if (cipher === undefined) {
                return null;
            }
            else {
                const address = new libsignal.ProtocolAddress(cipher.addr.id, cipher.addr.deviceId);
                return address;
            }
        });
    }
}
exports.SignalClientStore = SignalClientStore;
//# sourceMappingURL=Store.js.map