/// <reference types="node" />
import { SignalServerStore } from './SignalServerStore';
export declare class Occultus {
    status: boolean;
    constructor(userId: string, password: string, SSS: SignalServerStore, clientStorePath: string);
    init(): Promise<void>;
    encrypt(userId: string, message: string): Promise<string>;
    decrypt(userId: string, cypher: string): Promise<string>;
}
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
    dataDir: string;
}
export interface SignalServerStoreInterface {
    config: ServerConfig;
    registerNewPreKeyBundle(userId: string, preKeyBundle: PreKeyBundle): Promise<boolean>;
    userIsExistant(userId: string): Promise<boolean>;
    getPreKeyBundle(userId: string): Promise<PreKeyBundle | undefined>;
}
