/// <reference types="node" />
export declare class SignalClientStore {
    protected Direction: {
        SENDING: 1;
        RECIEVING: 2;
    };
    private store;
    private userId;
    constructor(userId: string, password: string, dBPath: string);
    remove(key: string): Promise<void>;
    get(key: string): any;
    put(key: any, value: any): Promise<void>;
    getIdentityKeyPair(): Promise<{
        pubKey: Buffer;
        privKey: Buffer;
    }>;
    isTrustedIdentity(protocolAddressIdentifier: string, identityKey: Buffer): Promise<boolean>;
    getOurRegistrationId(): Promise<number>;
    getOurIdentity(): Promise<{
        pubKey: Buffer;
        privKey: Buffer;
    }>;
    loadIdentityKey(protocolAddressIdentifier: any): Promise<ArrayBuffer>;
    saveIdentity(protocolAddressIdentifier: any, identityKey: Buffer): Promise<boolean>;
    loadPreKey(preKeyIdentity: string): Promise<{
        pubKey: Buffer;
        privKey: Buffer;
    }>;
    storePreKey(keyId: any, keyPair: {
        pubKey: Buffer;
        privKey: Buffer;
    }): Promise<{
        pubKey: Buffer;
        privKey: Buffer;
    }>;
    removePreKey(keyId: any): Promise<boolean>;
    loadSignedPreKey(preKeyIdentity: string): Promise<{
        pubKey: Buffer;
        privKey: Buffer;
    }>;
    storeSignedPreKey(keyId: any, signedKeyPair: {
        pubKey: Buffer;
        privKey: Buffer;
    }): Promise<{
        pubKey: Buffer;
        privKey: Buffer;
    }>;
    removeSignedPreKey(keyId: any): Promise<any>;
    loadSession(identifier: string): Promise<any>;
    storeSession(protocolAddressIdentifier: string, record: any): Promise<any>;
    removeSession(protocolAddressIdentifier: any): Promise<any>;
    removeAllSessions(protocolAddressIdentifier: any): Promise<any>;
    storeSessionCipher(protocolAddressIdentifier: any, cipher: any): void;
    loadSessionCipherAddress(protocolAddressIdentifier: any): Promise<any>;
}
