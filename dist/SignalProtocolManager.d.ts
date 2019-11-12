import { SignalServerStore } from './SignalServerStore';
import { SignalClientStore } from './SignalClientStore';
export default class SignalProtocolManager {
    private readonly userId;
    private contacts;
    private readonly store;
    private readonly signalServerStore;
    constructor(userId: string, signalServerStore: SignalServerStore, clientStore: SignalClientStore);
    initializeAsync(): Promise<void>;
    private encryptMessageAsync;
    private decryptMessageAsync;
    private generatePreKeyBundleAsync;
    private processPrekey;
}
