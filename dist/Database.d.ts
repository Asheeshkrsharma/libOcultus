export declare class ClientStoreDataBase {
    private database;
    private encryptionKey;
    private IV;
    private adapter;
    private encryptionKeyPath;
    private userPasswordHash;
    constructor(userId: string, password: string, dBpath: string);
    get(key: string): any;
    set(key: string, value: any): boolean;
    remove(key: string): Promise<void>;
    private generateKey;
    private encrypt;
    private decrypt;
}
