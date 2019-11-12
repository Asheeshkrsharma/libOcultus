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
Object.defineProperty(exports, "__esModule", { value: true });
const Converters = __importStar(require("./Converter"));
const libsignal = require('libsignal');
class SignalProtocolManager {
    constructor(userId, signalServerStore, clientStore) {
        this.contacts = [];
        this.userId = userId;
        this.store = clientStore;
        this.signalServerStore = signalServerStore;
    }
    initializeAsync() {
        return __awaiter(this, void 0, void 0, function* () {
            const isUserExistantOnServer = yield this.signalServerStore.userIsExistant(this.userId);
            const isUserExistantOnClient = ((yield this.store.get('identityKey')) === undefined) ? false : true;
            const isUserExistant = isUserExistantOnServer && isUserExistantOnClient;
            if (!isUserExistant) {
                const identityKey = yield libsignal.keyhelper.generateIdentityKeyPair();
                const registrationId = yield libsignal.keyhelper.generateRegistrationId();
                this.store.put('identityKey', identityKey);
                this.store.put('registrationId', registrationId);
                const preKeyBundle = yield this.generatePreKeyBundleAsync(123, 456);
                try {
                    yield this.signalServerStore.registerNewPreKeyBundle(this.userId, preKeyBundle);
                }
                catch (error) {
                    throw new Error('Internal server Error');
                }
            }
            const contacts = yield this.store.get('contacts');
            this.contacts = contacts === undefined ? [] : contacts;
        });
    }
    encryptMessageAsync(remoteUserId, message) {
        return __awaiter(this, void 0, void 0, function* () {
            const bufferMsg = Converters.toBuffer(message);
            const newUser = this.contacts.includes(remoteUserId) === false ? true : false;
            const address = new libsignal.ProtocolAddress(Buffer.from(remoteUserId).toString('base64'), 123);
            const sessionCipher = new libsignal.SessionCipher(this.store, address);
            if (newUser) {
                this.contacts.push(remoteUserId);
                this.store.put('contacts', this.contacts);
                const remoteUserKey = yield this.signalServerStore.getPreKeyBundle(remoteUserId);
                const remoteUserPreKey = this.processPrekey(remoteUserKey);
                if (remoteUserPreKey !== undefined) {
                    const builder = new libsignal.SessionBuilder(this.store, address);
                    yield builder.initOutgoing(remoteUserPreKey);
                }
                else {
                    throw new Error('Server was irresponsive');
                }
                const cipherText = yield sessionCipher.encrypt(bufferMsg);
                return cipherText;
            }
            else {
                const sessionId = `${Buffer.from(remoteUserId).toString('base64')}.123`;
                const session = yield this.store.loadSession(sessionId);
                if (session === undefined) {
                    const wait = (ms) => new Promise((r, _j) => setTimeout(r, ms));
                    yield (() => __awaiter(this, void 0, void 0, function* () {
                        yield wait(1);
                        yield this.encryptMessageAsync(remoteUserId, message);
                    }))();
                }
                const cipherText = yield sessionCipher.encrypt(bufferMsg);
                return cipherText;
            }
        });
    }
    decryptMessageAsync(remoteUserId, cipherText) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const address = new libsignal.ProtocolAddress(Buffer.from(remoteUserId)
                    .toString('base64'), 123);
                const sessionCipher = yield new libsignal.SessionCipher(this.store, address);
                const sessionId = `${Buffer.from(remoteUserId).toString('base64')}.123`;
                const session = yield this.store.loadSession(sessionId);
                const decryptedMessage = cipherText.type === 1 ? yield sessionCipher
                    .decryptWhisperMessage(cipherText.body) : yield sessionCipher
                    .decryptPreKeyWhisperMessage(cipherText.body);
                return Converters.toString(decryptedMessage);
            }
            catch (error) {
                throw error;
            }
        });
    }
    generatePreKeyBundleAsync(preKeyId, signedPreKeyId) {
        return __awaiter(this, void 0, void 0, function* () {
            const identityKeyPair = yield this.store.getIdentityKeyPair();
            const registrationId = yield this.store.getOurRegistrationId();
            const preKeyPair = yield libsignal.keyhelper.generatePreKey(preKeyId);
            const signedPreKey = yield libsignal.keyhelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);
            this.store.storePreKey(preKeyPair.keyId, preKeyPair.keyPair);
            this.store.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair);
            return {
                identityKey: identityKeyPair.pubKey,
                registrationId,
                preKey: {
                    keyId: preKeyPair.keyId,
                    publicKey: preKeyPair.keyPair.pubKey
                },
                signedPreKey: {
                    keyId: signedPreKey.keyId,
                    publicKey: signedPreKey.keyPair.pubKey,
                    signature: signedPreKey.signature
                }
            };
        });
    }
    processPrekey(preKey) {
        if (preKey !== undefined) {
            return {
                identityKey: Buffer.from(preKey.identityKey),
                registrationId: preKey.registrationId,
                preKey: {
                    keyId: preKey.preKey.keyId,
                    publicKey: Buffer.from(preKey.preKey.publicKey)
                },
                signedPreKey: {
                    keyId: preKey.signedPreKey.keyId,
                    publicKey: Buffer.from(preKey.signedPreKey.publicKey),
                    signature: Buffer.from(preKey.signedPreKey.signature)
                }
            };
        }
        else {
            return undefined;
        }
    }
}
exports.default = SignalProtocolManager;
//# sourceMappingURL=SignalProtocolManager.js.map