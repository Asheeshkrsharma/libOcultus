import * as Converters from './Converter';

import { ClientStoreDataBase } from './Database';
import path from 'path';

// tslint:disable-next-line: no-var-requires
const libsignal = require('libsignal');
const SessionRecord = libsignal.SessionRecord;

/**
 * Storage Interface is used to store things on device (aka client)
 */
interface StorageInterface {
    [key: string]: any;
}

/**
 * A libsignal client needs to implement a storage interface
 * that will manage loading and storing of identity, prekeys,
 * signed prekeys, and session state
 */

const privates = new WeakMap();

export class SignalClientStore {
// tslint:disable-next-line: variable-name
    protected Direction!: {
        SENDING: 1;
        RECIEVING: 2;
    };

    private store: StorageInterface;
    private userId: string;

    /**
     * We just implement the internals here privately.
     * All the stuff is saved. This includes
     * loading and storing stuff to an encrypted file.
     */
    constructor(userId: string, password: string, dBPath: string) {
        this.store = {};
        this.userId = userId;
        dBPath = `${path.resolve(dBPath)}/`;
        privates.set(this, {
            _database: new ClientStoreDataBase(this.userId, password, dBPath)
        });

        this.store = new Proxy(this.store, {
            deleteProperty: (target, property: string): boolean => {
                if (property === null || property === undefined) {
                    throw new Error('Tried to remove value for undefined/null key');
                    return false;
                }
                privates.get(this)._database.remove(property);
                // console.log(`deleted ${property}`);
                delete target[property];
                return true;
            },
            set: (target, property: string, value: any): boolean => {
                if (property === undefined || value === undefined
                    || property === null || value === null) {
                    throw new Error('Tried to store undefined/null');
                }
                target[property] = value;
                privates.get(this)._database.set(property, value);
                return true;
            },
            get: (target, property: string): any => {
                let value: any;
                if (property === null || property === undefined) {
                    throw new Error('Tried to get value for undefined/null key');
                }
                if (property in target) {
                    value = target[property];
                } else {
                    // A crappy way to sync
                    value = privates.get(this)._database.get(property);
                    if (target[property] !== value) {
                        target[property] = value;
                    }
                }
                return value;
            }
        });
    }

    public remove(key: string) {
        delete this.store[key];
    }

    public get(key: string) {
        return this.store[key];
    }

    public put(key: any, value: any) {
        this.store[key] = value;
    }

    public async getIdentityKeyPair(): Promise<{ pubKey: Buffer; privKey: Buffer; }> {
        return await Promise.resolve(this.store['identityKey']);
    }

    /**
     * Used to type check identity key
     * @param protocolAddressIdentifier Identifier of the address generated
     * by the libsignal protocol
     * @param identityKey Curve25519 key
     */
    public async isTrustedIdentity(protocolAddressIdentifier: string,
                                   identityKey: Buffer): Promise<boolean> {
        // Type checks
        if (protocolAddressIdentifier === null ||
            protocolAddressIdentifier === undefined) {
            throw new Error('Tried to check identity key for undefined/null key');
        }
        if (!(identityKey instanceof Buffer)) {
            throw new Error('Expected identityKey to be a Buffer');
        }

        const trusted = await this.store['identityKey' + protocolAddressIdentifier];

        // Check if the identity related to this address is defined.
        // if it is not, maybe someone did something suspecious.
        if (trusted === undefined) {
            return Promise.resolve(true);
        }

        // Final check.
        return await Promise.resolve(Converters.toString(identityKey)
            === Converters.toString(trusted));
    }

    /**
     * Return the registration id
     */
    public async getOurRegistrationId(): Promise<number> {
        return await Promise.resolve(this.store['registrationId']);
    }

    /**
     * Return the identity keyPair
     */
    public async getOurIdentity():
        Promise<{ pubKey: Buffer, privKey: Buffer }> {
        let res = await this.store['identityKey'];
        if (res !== undefined) {
            if (res.pubKey.type === 'Buffer') {
                res = {
                    pubKey: Buffer.from(res.pubKey.data),
                    privKey: Buffer.from(res.privKey.data)
                };
            }
        }
        return Promise.resolve(res);
    }

    /**
     * load identity key
     * @param protocolAddressIdentifier Identifier of the address generated
     * by the libsignal protocol
     */
    public async loadIdentityKey(protocolAddressIdentifier: any): Promise<ArrayBuffer> {
        if (protocolAddressIdentifier === null
            || protocolAddressIdentifier === undefined) {
            throw new Error('Tried to get identity key for undefined/null key');
        }

        return await Promise.resolve(
            this.store['identityKey' + protocolAddressIdentifier]);
    }

    /**
     * Save the identity
     * @param protocolAddressIdentifier Identifier of the address generated
     * by the libsignal protocol
     * @param identityKey Curve25519 key
     */
    public async saveIdentity(protocolAddressIdentifier: any, identityKey: Buffer):
        Promise<boolean> {
        if (protocolAddressIdentifier === null ||
            protocolAddressIdentifier === undefined) {
            throw new Error('Tried to put identity key for undefined/null key');
        }

        const address = new libsignal.SignalProtocolAddress.fromString(
            protocolAddressIdentifier
        );

        const existing = this.store['identityKey' + address.getName()];
        this.store['identityKey' + address.getName()] = identityKey;

        if (existing && Converters.toString(identityKey) !==
            Converters.toString(existing)) {
            return await Promise.resolve(true);
        } else {
            return await Promise.resolve(false);
        }
    }

    /**
     * Returns a prekeypair object or undefined
     * @param preKeyIdentity prekey identity attached to
     * a message in a session
     */
    public async loadPreKey(preKeyIdentity: string):
        Promise<{ pubKey: Buffer, privKey: Buffer }> {
        let res = await this.store['25519KeypreKey' + preKeyIdentity];
        if (res !== undefined) {
            if (res.pubKey.type === 'Buffer') {
                res = {
                    pubKey: Buffer.from(res.pubKey.data),
                    privKey: Buffer.from(res.privKey.data)
                };
            }
        }
        return Promise.resolve(res);
    }

    /**
     * Store the prekey
     * @param keyId used to access the key
     * @param keyPair The prekey pair
     */
    public async storePreKey(keyId: any, keyPair:
        { pubKey: Buffer, privKey: Buffer }) {
        return await Promise.resolve(
            this.store['25519KeypreKey' + keyId] = keyPair);
    }

    /**
     * Remove prekey
     * @param keyId The prekey pair
     */
    public async removePreKey(keyId: any) {
        return await Promise.resolve(
            delete this.store['25519KeypreKey' + keyId]);
    }

    /**
     * Returns a signed keypair object or undefined
     * @param preKeyIdentity prekey identity attached to
     * a message in a session
     */
    public async loadSignedPreKey(preKeyIdentity: string):
        Promise<{ pubKey: Buffer, privKey: Buffer }> {
        let res = await this.store['25519KeysignedKey' + preKeyIdentity];
        if (res !== undefined) {
            if (res.pubKey.type === 'Buffer') {
                res = {
                    pubKey: Buffer.from(res.pubKey.data),
                    privKey: Buffer.from(res.privKey.data)
                };
            }
        }
        return Promise.resolve(res);
    }

    /**
     * Store the signed prekey
     * @param keyId used to access the key
     * @param signedKeyPair the signed key pair
     */
    public async storeSignedPreKey(keyId: any, signedKeyPair:
        { pubKey: Buffer, privKey: Buffer }) {
        return await Promise.resolve(
            this.store['25519KeysignedKey' + keyId] = signedKeyPair);
    }

    /**
     * Remove signed prekey
     * @param keyId used to access the key
     */
    public async removeSignedPreKey(keyId: any): Promise<any> {
        return await Promise.resolve(
            delete this.store['25519KeysignedKey' + keyId]);
    }

    /**
     * Load session with a particular identifier
     * @param identifier Identifier of the address generated
     * by the libsignal protocol
     */
    public async loadSession(identifier: string): Promise<any> {
        const sessionRecordJson = await this.store['session' + identifier];
        return Promise.resolve( sessionRecordJson
            !== undefined ? SessionRecord.deserialize(sessionRecordJson) : undefined);
    }

    /**
     * Load session with a particular identifier
     * @param identifier Identifier of the address generated
     * by the libsignal protocol
     * @param record a libsignal SessionRecord
     */
    public async storeSession(protocolAddressIdentifier: string, record: any): Promise<any> {
        const serialized = await record.serialize();
        this.store['session' + protocolAddressIdentifier] = serialized;
    }

    /**
     * Remove all sessions
     * @param protocolAddressIdentifier prekey identity attached to
     * a message in a session
     */
    public async removeSession(protocolAddressIdentifier: any): Promise<any> {
        return await
            Promise.resolve(
                delete this.store['session' + protocolAddressIdentifier]
            );
    }

    /**
     * Remove all sessions
     * @param protocolAddressIdentifier prekey identity attached to
     * a message in a session
     */
    public async removeAllSessions(protocolAddressIdentifier: any): Promise<any> {
        for (const id in this.store) {
            if (id.startsWith('session' + protocolAddressIdentifier)) {
                delete this.store[id];
            }
        }
        return await Promise.resolve();
    }
}
