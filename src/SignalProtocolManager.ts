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
    private contacts: string[] = [];
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

            this.store.put('identityKey', identityKey);
            this.store.put('registrationId', registrationId);
            const preKeyBundle = await this.generatePreKeyBundleAsync(123, 456);
            try {
                await this.signalServerStore.registerNewPreKeyBundle(this.userId, preKeyBundle);
            } catch (error) {
                throw new Error('Internal server Error');
            }
        }
        const contacts = await this.store.get('contacts');
        this.contacts = contacts === undefined ? [] : contacts;
    }

    /**
     * Encrypt a message for a given user.
     *
     * @param remoteUserId The recipient user ID.
     * @param message The message to send.
     */
    private async encryptMessageAsync(remoteUserId: string, message: string) {
        const bufferMsg = Converters.toBuffer(message);
        const newUser = this.contacts.includes(remoteUserId) === false ? true : false;
        const address = new libsignal.ProtocolAddress(
            Buffer.from(remoteUserId).toString('base64'), 123);
        const sessionCipher = new libsignal.SessionCipher(this.store, address);

        // Check if we have seen this contact previously.
        if (newUser) {
            // If we have not, initilizae a new session for this user.
            this.contacts.push(remoteUserId); // Push to contacts.
            this.store.put('contacts', this.contacts); // Update the store.

            // Get a prekey bundle for this user from the server and process it.
            const remoteUserKey = await
                this.signalServerStore.getPreKeyBundle(remoteUserId);
            const remoteUserPreKey = this.processPrekey(remoteUserKey);

            // If we recieved a prekey bundle from the user, we store initiate a
            // new session
            if (remoteUserPreKey !== undefined) {
                const builder = new libsignal.SessionBuilder(this.store, address);
                await builder.initOutgoing(remoteUserPreKey);
            } else {
                // Else, there was some error at the server.
                throw new Error('Server was irresponsive');
            }
            // Now encrypt.
            const cipherText = await sessionCipher.encrypt(bufferMsg);
            return cipherText;
        } else {
            // There is a big chance that the user has been previously seen
            // but a session has not been created for it yet. So we check for that first
            const sessionId = `${Buffer.from(remoteUserId).toString('base64')}.123`;
            const session = await this.store.loadSession(sessionId);
            if (session === undefined) {
                // If the session was undefined, but user is existant. We should
                // sanely wait for the session to open.
                const wait = (ms: number) => new Promise((r, _j) => setTimeout(r, ms));
                await (async () => {
                    await wait(1); // wait for a millisecond
                    // Call this function again.
                    await this.encryptMessageAsync(remoteUserId, message);
                })();
            }
            // Finally excrypt the text.
            // Here the cipher type is set to 1. Which means that it does not carry
            // a prekeybundle with it.
            const cipherText = await sessionCipher.encrypt(bufferMsg);
            return cipherText;
        }
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
        // We put this in a try-catch sequence for safety.
        try {
            const address: any = new libsignal.ProtocolAddress(Buffer.from(remoteUserId)
            .toString('base64'), 123);
            const sessionCipher = await new libsignal.SessionCipher(this.store, address);
            const sessionId = `${Buffer.from(remoteUserId).toString('base64')}.123`;
            const session = await this.store.loadSession(sessionId);
            // Check the type of cipher. If it is type-1, it does not have a prekey
            // bundle attached to it. In that case, we normally decrypt it. Otherwise
            // It will be a type-3 message; use decryptPreKeyWhisperMessage in that
            // case.
            const decryptedMessage = cipherText.type === 1 ? await sessionCipher
            .decryptWhisperMessage(cipherText.body) : await sessionCipher
            .decryptPreKeyWhisperMessage(cipherText.body);

            // Convert the buffer to string and return.
            return Converters.toString(decryptedMessage);
        } catch (error) {
            throw error;
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

    /**
     * Function to process an incoming prekey bundle.
     * @param preKey The prekey bundle to precess.
     */
    private processPrekey(preKey: PreKeyBundle | undefined) {
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
        } else {
            return undefined;
        }
    }
}
