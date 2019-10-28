import SignalProtocolManager from './SignalProtocolManager';
import { SignalServerStore } from './SignalServerStore';
import { SignalClientStore } from './SignalClientStore';

const privates = new WeakMap();

// The exported class which is expose to the
// outside world.
/**
 * This will hold the signal protocol manager. Since we are not going expose the privates to the
 * outside world, there is no way for the interfaces built on occult to have the accesess to the
 * internals of signal protocol manager. This wrapper on Signal Protocol manager initialises
 * the actual one and exposes two methods for encyption and decryption.
 */
export class Occultus {
    /**
     * Class to instantiate encryption and decryption routines.
     * @param userId The userId used to initialize the signal protocol manager.
     * @param SSS The signal server store, to exchange prekey information
     * @param clientStorePath local directory where the user database and its key is supposed to
     * be stored. This is completely safe as long as you key is hidden.
     */
    constructor(userId: string, password: string, SSS: SignalServerStore,
        clientStorePath: string) {
        privates.set(this, {
            _SPMPrivate: new SignalProtocolManager(userId,
                SSS,
                new SignalClientStore(userId, password, clientStorePath))
        });
    }

    /**
     * Intialization. Meant to be run just after an instance of this class
     * has been created.
     */
    public async init() {
        await privates.get(this)._SPMPrivate.initializeAsync();
    }

    /**
     * Encrypt an message for a particular user.
     * @param userId The userId for which the message should be encrypted.
     * @param message The message.
     */
    public async encrypt(userId: string, message: string): Promise<string> {
        return await privates.get(this)
            ._SPMPrivate.encryptMessageAsync(userId, message);
    }

    /**
     * Decrypt a message from a particular user.
     * @param userId The userId using which the message was encrypted.
     * @param cypher The encrpted message.
     */
    public async decrypt(userId: string, cypher: string):
        Promise<{ message: string, isNewUser: boolean }> {
        return await privates.get(this)
            ._SPMPrivate.decryptMessageAsync(userId, cypher);
    }
}

// The Server side communication is handled by the implementation
// of the SignalServerStoreInterface, outside Occultus.
export interface PreKeyBundle {
    identityKey: Buffer;
    registrationId: number;
    preKey: {
        keyId: number;
        publicKey: Buffer;
    };
    signedPreKey: {
        keyId: number;
        publicKey: Buffer;
        signature: Buffer;
    };
}

export interface ServerConfig {
    apiURL: string;
    apiKey: string;
    login: {
        username: string;
        password: string;
    };
}

export interface SignalServerStoreInterface {
    config: ServerConfig;
    /**
     * When a user logs on they should generate their keys and
     * then register them with the server.
     * @param userId The user ID.
     * @param preKeyBundle The user's generated pre-key bundle.
     */
    registerNewPreKeyBundle(userId: string, preKeyBundle: PreKeyBundle): Promise<boolean>;
    /**
     * Check if a user id exists
     * @param userId
     */
    userIsExistant(userId: string): Promise<boolean>;
    /**
     * Gets the pre-key bundle for the given user ID.
     * If you want to start a conversation with a user,
     * you need to fetch their pre-key bundle first.
     * @param userId The ID of the user.
     */
    getPreKeyBundle(userId: string): Promise<PreKeyBundle | undefined>;
}
