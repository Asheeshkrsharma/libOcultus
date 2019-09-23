import { SignalServerStore, PreKeyBundle } from './SignalServerStore';
import { SignalClientStore } from './SignalClientStore';
import * as Converters from './Converter';
// tslint:disable-next-line: no-var-requires
const libsignal = require('libsignal');

/**
 * A signal protocol manager.
 */
export default class SignalProtocolManager {
    private readonly userId: string;

    // A libsignal client needs to implement a storage interface
    // that will manage loading and storing of identity, prekeys,
    // signed prekeys, and session state.

    private readonly store: SignalClientStore;
    private readonly signalServerStore: SignalServerStore;
    constructor(userId: string, signalServerStore: SignalServerStore,
                clientStore: SignalClientStore) {
        this.userId = userId;
        this.store = clientStore;
        this.signalServerStore = signalServerStore;
    }

    /**
     * Initialize the manager when the user logs on.
     */
    public async initializeAsync() {
        const isUserExistantOnServer = await this.signalServerStore.userIsExistant(this.userId);
        const isUserExistantOnClient =
            (await this.store.get('identityKey') === undefined) ? false : true;

        const isUserExistant = isUserExistantOnServer && isUserExistantOnClient;
        if (!isUserExistant) {
            const identityKey = await libsignal.keyhelper.generateIdentityKeyPair();
            const registrationId = await libsignal.keyhelper.generateRegistrationId();

            await this.store.put('identityKey', identityKey);
            await this.store.put('registrationId', registrationId);
            const preKeyBundle = await this.generatePreKeyBundleAsync(123, 456);
            try {
                await this.signalServerStore.registerNewPreKeyBundle(this.userId, preKeyBundle);
            } catch (error) {
                throw new Error('Internal server Error');
            }
        }
    }

    /**
     * Encrypt a message for a given user.
     *
     * @param remoteUserId The recipient user ID.
     * @param message The message to send.
     */
    private async encryptMessageAsync(remoteUserId: string, message: string) {
        const address = await this.store.loadSessionCipherAddress(remoteUserId);
        let sessionCipher;

        if (address === null) {
            const newAddress = new libsignal.ProtocolAddress(
                Buffer.from(remoteUserId).toString('base64'), 123);
            const sessionBuilder = new libsignal.SessionBuilder(this.store, newAddress);
            let remoteUserPreKey: PreKeyBundle | undefined = await
                this.signalServerStore.getPreKeyBundle(remoteUserId);

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
        } else {
            sessionCipher = new libsignal.SessionCipher(this.store, address);
        }
        const bufferMsg = Converters.toBuffer(message);
        const cipherText = await sessionCipher.encrypt(bufferMsg);
        return cipherText;
    }

    /**
     * Decrypts a message from a given user.
     *
     * @param remoteUserId The user ID of the message sender.
     * @param cipherText The encrypted message bundle.
     * (This includes the encrypted message itself and accompanying metadata)
     * @returns The decrypted message string.
     */
    private async decryptMessageAsync(remoteUserId: string, cipherText: any) {
        const address: any = await this.store.loadSessionCipherAddress(remoteUserId);
        let sessionCipher;
        if (address == null) {
            const newAddress = new libsignal.ProtocolAddress(Buffer.from(remoteUserId)
                .toString('base64'), 123);
            sessionCipher = await new libsignal.SessionCipher(this.store, newAddress);
            this.store.storeSessionCipher(remoteUserId, sessionCipher);
        } else {
            sessionCipher = await new libsignal.SessionCipher(this.store, address);
        }

        const messageHasEmbeddedPreKeyBundle = cipherText.type === 3;
        if (messageHasEmbeddedPreKeyBundle) {
            const decryptedMessage = await sessionCipher
                .decryptPreKeyWhisperMessage(cipherText.body, 'binary');
            return Converters.toString(decryptedMessage);
        } else {
            const decryptedMessage = await sessionCipher
                .decryptWhisperMessage(cipherText.body, 'binary');
            return Converters.toString(decryptedMessage);
        }
    }

    /**
     * Generates a new pre-key bundle for the local user.
     *
     * @param preKeyId An ID for the pre-key.
     * @param signedPreKeyId An ID for the signed pre-key.
     * @returns A pre-key bundle.
     */
    private async generatePreKeyBundleAsync(preKeyId: number,
                                            signedPreKeyId: number): Promise<PreKeyBundle> {
        // Registration

        // Store identityKeyPair somewhere durable and safe.
        // A long-term Curve25519 key pair, generated at install time.
        const identityKeyPair = await this.store.getIdentityKeyPair();

        // Store registrationId somewhere durable and safe.
        const registrationId = await this.store.getOurRegistrationId();

        // One-Time Pre Keys – A queue of Curve25519 key pairs for one
        // time use, generated at install time, and replenished as needed.
        const preKeyPair = await libsignal.keyhelper.generatePreKey(preKeyId);

        // Signed Pre Key
        // A medium-term Curve25519 key pair, generated at install time,
        // signed by the Identity Key, and rotated on a periodic timed basis.
        const signedPreKey = await libsignal.keyhelper.generateSignedPreKey(identityKeyPair,
            signedPreKeyId);

        // Store 'em
        this.store.storePreKey(preKeyPair.keyId, preKeyPair.keyPair);
        this.store.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair);

        // According to Whatsapp's whitepaper;
        // https://www.whatsapp.com/security/WhatsApp-Security-Whitepaper.pdf
        // At registration time, a WhatsApp client transmits its public Identity
        // Key, public Signed Pre Key (with its signature), and a batch of public
        // One-Time Pre Keys to the server. The WhatsApp server stores these
        // public keys associated with the user’s identifier. At no time does the
        // WhatsApp server have access to any of the client’s private keys.

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
    }
}
