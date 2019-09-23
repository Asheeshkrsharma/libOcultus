import { expect } from 'chai';
import * as Occultus from '../dist/index';
import { SignalServerStore } from './serverstoreDummy.spec';
import fs from 'fs';

import { describe, it } from 'mocha';

const dataDirectory = './test/tmp/';

describe('Validations tests on Occultus', () => {
    it('Make a signal server store', async () => {
        const serverStoreConfig = {
            apiURL: '',
            apiKey: '',
            login: {
                username: '',
                password: ''
            }
        };
        // Create an instance of Signal Server Store.
        const SSS = new SignalServerStore(serverStoreConfig);
        // Check the properties and methods
        expect(SSS.config).to.equal(serverStoreConfig);

        // User 'sadasds' does not exists in the store.
        // So this should return false.
        expect(await SSS.userIsExistant('sadasds')).to.equal(false);
    });
    it('Test signal server store: Register and Retrieve a certain user\'s prekey bundle',
        async () => {
            const serverStoreConfig = {
                apiURL: '',
                apiKey: '',
                login: {
                    username: '',
                    password: ''
                }
            };

            // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
            fs.mkdirSync(dataDirectory);

            // Create an instance of Signal Server Store.
            const SSS = new SignalServerStore(serverStoreConfig);
            const u1OC = new Occultus.Occultus('asas', 'asdasd' , SSS, dataDirectory);
            await u1OC.init();

            expect(await SSS.userIsExistant('asas')).to.equal(true);

            const preKeyBundle: any = (await SSS.getPreKeyBundle('asas'));

            // PrekeyBundle should have following properties with the types.
            const type: Occultus.PreKeyBundle | undefined = {
                identityKey: Buffer.from(''),
                registrationId: 2,
                preKey:
                {
                    keyId: 5,
                    publicKey: Buffer.from('')
                },
                signedPreKey:
                {
                    keyId: 6,
                    publicKey: Buffer.from(''),
                    signature: Buffer.from('')
                }
            };

            // Check if the properties exist.
            expect(JSON.stringify(Object.keys(preKeyBundle).sort()))
                .to.equal(JSON.stringify(Object.keys(type).sort()));

            // Get a prekey bundle from a non-existant user.
            expect(await SSS.getPreKeyBundle('assaas')).to.equal(undefined);
        });
    it('Run encryption/decrption routine', async () => {
        const serverStoreConfig = {
            apiURL: '',
            apiKey: '',
            login: {
                username: '',
                password: ''
            }
        };
        // Create an instance of Signal Server Store.
        const SSS = new SignalServerStore(serverStoreConfig);
        const u1OC = new Occultus.Occultus('user11', 'asdasd', SSS, dataDirectory);
        await u1OC.init();

        const u2OC = new Occultus.Occultus('user12', 'asdasd', SSS, dataDirectory);
        await u2OC.init();

        const message = 'how you doing?';
        const encrypted = await u1OC.encrypt('user12', message);
        const decrypted = await u2OC.decrypt('user11', encrypted);
        expect(decrypted).to.equal(message);
    });
    it('Run encryption/decrption routine with someone eves dropping', async () => {
        const serverStoreConfig = {
            apiURL: '',
            apiKey: '',
            login: {
                username: '',
                password: ''
            }
        };
        // Create an instance of Signal Server Store.
        const SSS = new SignalServerStore(serverStoreConfig);
        const u1OC = new Occultus.Occultus('user1', 'asdasd',  SSS, dataDirectory);
        await u1OC.init();

        const u2OC = new Occultus.Occultus('user2', 'asdasd', SSS, dataDirectory);
        await u2OC.init();

        const u3OC = new Occultus.Occultus('user3', 'asdasd', SSS, dataDirectory);
        await u3OC.init();

        const message = 'how you doing?';
        const encrypted = await u1OC.encrypt('user2', message);
        const decrypted = await u2OC.decrypt('user1', encrypted);
        expect(decrypted).to.equal(message);

        let result;
        try {
            result = await u3OC.decrypt('asas', encrypted);
        } catch (error) {
            result = error.toString();
        }
        expect(result).to.equal('Error: Bad MAC');
    });
    it('Re-generate client-side store keys randomly b/w writes.',
    async () => {
        const serverStoreConfig = {
            apiURL: '',
            apiKey: '',
            login: {
                username: '',
                password: ''
            }
        };
        // Create an instance of Signal Server Store.
        const SSS = new SignalServerStore(serverStoreConfig);
        const u1OC = new Occultus.Occultus('user3', 'asdasd', SSS, dataDirectory);
        u1OC.init();

        // Get the encryption key
        let userId = Buffer.from('user3').toString('base64');
        let keyPath: string = `${dataDirectory}${userId}.key`;
        // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
        const u1EncryptionKeyBefore = fs.readFileSync(`${keyPath}`, 'ascii').toString();

        const u2OC = new Occultus.Occultus('user4', 'asdasd', SSS, dataDirectory);
        await u2OC.init();

        // Get the encryption key
        userId = Buffer.from('user4').toString('base64');
        keyPath = `${dataDirectory}${userId}.key`;
        // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
        const u2EncryptionKeyBefore = fs.readFileSync(`${keyPath}`, 'ascii').toString();

        const message = 'how you doing?';
        const encrypted = await u1OC.encrypt('user4', message);
        const decrypted = await u2OC.decrypt('user3', encrypted);

        // check if the encryption key is same or not.
        // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
        const u2EncryptionKeyAfter = fs.readFileSync(`${keyPath}`, 'ascii').toString();

        userId = Buffer.from('user3').toString('base64');
        keyPath = `${dataDirectory}${userId}.key`;
        // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
        const u1EncryptionKeyAfter = fs.readFileSync(`${keyPath}`, 'ascii').toString();

        expect(u1EncryptionKeyAfter).to.not.equal(u1EncryptionKeyBefore);
        expect(u2EncryptionKeyAfter).to.not.equal(u2EncryptionKeyBefore);
    });
    it('Check client store database authentication system by spoofing', async () => {
        const serverStoreConfig = {
            apiURL: '',
            apiKey: '',
            login: {
                username: '',
                password: ''
            }
        };
        // Create an instance of Signal Server Store.
        const SSS = new SignalServerStore(serverStoreConfig);
        const u1OC = new Occultus.Occultus('user11', 'asdasd', SSS, dataDirectory);
        await u1OC.init();

        let result;
        try {
            result = new Occultus.Occultus('user11', 'asdasdasd', SSS, dataDirectory);
        } catch (error) {
            result = error.toString();
        }
        expect(result).to.equal('Error: Authentication failed');
    });
    it('Avoid module loading using a variable: Check clientstore private accesibility.',
    async () => {
        const serverStoreConfig = {
            apiURL: '',
            apiKey: '',
            login: {
                username: '',
                password: ''
            }
        };
        // Create an instance of Signal Server Store.
        const SSS = new SignalServerStore(serverStoreConfig);
        const u1OC = new Occultus.Occultus('user1', 'asdasd', SSS, dataDirectory);
        expect(u1OC instanceof Occultus.Occultus).to.equal(true);

        const deleteFolderRecursive = (path: string) => {
            // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
            if (fs.existsSync(path)) {
                // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
                fs.readdirSync(path).forEach((file, _) => {
                    const curPath = path + '/' + file;
                    // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
                    if (fs.lstatSync(curPath).isDirectory()) { // recurse
                        deleteFolderRecursive(curPath);
                    } else { // delete file
                        // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
                        fs.unlinkSync(curPath);
                    }
                });
                // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
                fs.rmdirSync(path);
            }
        };
        deleteFolderRecursive(dataDirectory);
    });
});
