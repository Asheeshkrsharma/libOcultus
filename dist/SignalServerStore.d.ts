/// <reference types="node" />
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
export interface SignalServerStore {
    config: ServerConfig;
    registerNewPreKeyBundle(userId: string, preKeyBundle: PreKeyBundle): Promise<boolean>;
    userIsExistant(userId: string): Promise<boolean>;
    getPreKeyBundle(userId: string): Promise<PreKeyBundle | undefined>;
}
