import * as Occultus from '../dist/index';
import fetch from 'node-fetch';

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
        const getData = async () => {
            try {
                const response = await fetch('http://localhost:8080/registerNewPreKeyBundle/', {
                method: 'post',
                body: JSON.stringify({
                        userId,
                        bundle: preKeyBundle
                }),
                headers: { 'Content-Type': 'application/json' },
            });
                const json = await response.json();
                return json;
            } catch (error) {
                throw error;
            }
            };
        return getData();
    }

    public async userIsExistant(userId: string): Promise<boolean> {
        const getData = async () => {
            try {
              const response = await fetch('http://localhost:8080/userIsExistant/', {
                method: 'post',
                body: JSON.stringify({userId}),
                headers: { 'Content-Type': 'application/json' },
            });
              const json = await response.json();
              return json;
            } catch (error) {
              throw error;
            }
          };
        return getData();
    }

    public async getPreKeyBundle(userId: string): Promise<Occultus.PreKeyBundle | undefined> {
        const getData = async () => {
            try {
              const response = await fetch('http://localhost:8080/getPreKeyBundle/', {
                method: 'post',
                body: JSON.stringify({userId}),
                headers: { 'Content-Type': 'application/json' },
            });
              const json = await response.json();
              return json;
            } catch (error) {
              return undefined;
            }
          };
        return getData();
    }
}
