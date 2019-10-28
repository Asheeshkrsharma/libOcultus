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
const libsignal = require('libsignal');
class SignalProtocolManager {
    constructor(userId, signalServerStore, clientStore) {
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
                yield this.store.put('identityKey', identityKey);
                yield this.store.put('registrationId', registrationId);
                const preKeyBundle = yield this.generatePreKeyBundleAsync(123, 456);
                try {
                    yield this.signalServerStore.registerNewPreKeyBundle(this.userId, preKeyBundle);
                }
                catch (error) {
                    throw new Error('Internal server Error');
                }
            }
        });
    }
    encryptMessageAsync(remoteUserId, message) {
        return __awaiter(this, void 0, void 0, function* () {
            const address = yield this.store.loadSessionCipherAddress(remoteUserId);
            let sessionCipher;
            if (address === null) {
                const newAddress = new libsignal.ProtocolAddress(Buffer.from(remoteUserId).toString('base64'), 123);
                const sessionBuilder = new libsignal.SessionBuilder(this.store, newAddress);
                let remoteUserPreKey = yield this.signalServerStore.getPreKeyBundle(remoteUserId);
                if (remoteUserPreKey !== undefined) {
                    remoteUserPreKey = {
                        identityKey: Buffer.from(remoteUserPreKey.identityKey),
                        registrationId: remoteUserPreKey.registrationId,
                        preKey: {
                            keyId: remoteUserPreKey.preKey.keyId,
                            publicKey: Buffer.from(remoteUserPreKey.preKey.publicKey)
                        },
                        signedPreKey: {
                            keyId: remoteUserPreKey.signedPreKey.keyId,
                            publicKey: Buffer.from(remoteUserPreKey.signedPreKey.publicKey),
                            signature: Buffer.from(remoteUserPreKey.signedPreKey.signature)
                        }
                    };
                    sessionBuilder.initOutgoing(remoteUserPreKey);
                    sessionCipher = new libsignal.SessionCipher(this.store, newAddress);
                    this.store.storeSessionCipher(remoteUserId, sessionCipher);
                }
            }
            else {
                sessionCipher = new libsignal.SessionCipher(this.store, address);
            }
            const bufferMsg = Converters.toBuffer(message);
            const cipherText = yield sessionCipher.encrypt(bufferMsg);
            return cipherText;
        });
    }
    decryptMessageAsync(remoteUserId, cipherText) {
        return __awaiter(this, void 0, void 0, function* () {
            const address = yield this.store.loadSessionCipherAddress(remoteUserId);
            let sessionCipher;
            let isNewUser = false;
            if (address == null) {
                const newAddress = new libsignal.ProtocolAddress(Buffer.from(remoteUserId)
                    .toString('base64'), 123);
                sessionCipher = yield new libsignal.SessionCipher(this.store, newAddress);
                isNewUser = true;
                this.store.storeSessionCipher(remoteUserId, sessionCipher);
            }
            else {
                sessionCipher = yield new libsignal.SessionCipher(this.store, address);
            }
            const messageHasEmbeddedPreKeyBundle = cipherText.type === 3;
            if (messageHasEmbeddedPreKeyBundle) {
                const decryptedMessage = yield sessionCipher
                    .decryptPreKeyWhisperMessage(cipherText.body, 'binary');
                return { message: Converters.toString(decryptedMessage), isNewUser };
            }
            else {
                const decryptedMessage = yield sessionCipher
                    .decryptWhisperMessage(cipherText.body, 'binary');
                return { message: Converters.toString(decryptedMessage), isNewUser };
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
}
exports.default = SignalProtocolManager;
//# sourceMappingURL=SignalProtocolManager.js.map