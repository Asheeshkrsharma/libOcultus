import * as Occultus from '../dist/index';

/**
 * signal server database.
 * This component connects to thes signal server for
 * storing and fetching user public keys over HTTP.
 */
export class SignalServerStore implements Occultus.SignalServerStoreInterface {
    public config: Occultus.ServerConfig;
    private userBundles: Array<{ userId: string; prekeyBundle: Occultus.PreKeyBundle }>;
    constructor(config: Occultus.ServerConfig) {
        this.config = config;
        this.userBundles = [];
    }

    public async registerNewPreKeyBundle(userId: string,
                                         preKeyBundle: Occultus.PreKeyBundle)
        : Promise<boolean> {
        this.userBundles.push({
            userId,
            prekeyBundle: preKeyBundle
        });
        const success: boolean = true;
        return success;
    }

    public async userIsExistant(userId: string): Promise<boolean> {
        const isExistant = this.userBundles.findIndex((element) =>
            element.userId === userId) === -1 ? false : true;
        return isExistant;
    }

    public async getPreKeyBundle(userId: string): Promise<Occultus.PreKeyBundle | undefined> {
        const index = this.userBundles.findIndex((element) =>
            element.userId === userId);
        let preKeyBundle;
        if (index !== -1) {
            preKeyBundle = this.userBundles[index].prekeyBundle;
        }
        return preKeyBundle;
    }
}
