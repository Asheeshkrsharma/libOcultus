import lowdb = require('lowdb');
import FileSync = require('lowdb/adapters/FileSync');
import crypto from 'crypto';
import zlib from 'zlib';
import fs from 'fs';

// Used to encrypt database encryption key
import bcrypt from 'bcrypt';
const saltRounds = 10;

/**
 * This is the internal storage interface.
 * Handles the encryption and decrption.
 * Based on:
 * https://vancelucas.com/blog/stronger-encryption-and-decryption-in-node-js/
 * If your encryption method produces the same encrypted result given
 * the same original text input, your encryption is broken. Yet this
 * is what I see in most other examples around the web on how to do
 * encryption in Node.js. Strong encryption should always produce a
 * different output, even given the same exact input.
 *
 * But what does it matter if the content is encrypted anyways,
 * you ask? It matters because if attackers ever gain access to your
 * encrypted data, one of the first steps is to analyze it for
 * similarities and patterns. If multiple records have the same output
 * – even if the text is encrypted – that lets the attacker know that
 * the input for both those records was the same. That might not sound
 * like you’re giving up any valuable information, but it could be
 * enough information for the attacker to infer the content of other
 * encrypted records.
 *
 * For instance, if the attacker knows the original content of a single
 * encrypted record (perhaps even by using your service themselves),
 * they can scan the database for the same output result in other
 * records, and thus learn the contents of them as well. You can imagine
 * scenarios in which attackers will continue using your service to
 * encrypt things, then keep checking the database for the same results
 * to learn the contents of other encrypted records by brute-force.
 * Adding some randomness to ensure encrypted output is always different
 * prevents this attack vector.
 */

export class ClientStoreDataBase {
    private database: any;
    private encryptionKey: string;
    private IV: number; // Initialization Vector (IV)
    private adapter: any;
    private encryptionKeyPath: string;
    private userPasswordHash: string;

    /**
     * @param path path to the encrypted database
     * @param encryptionKey With AES encryption
     * (this uses aes-256-cbc), the IV length is always 16.
     */
    constructor(userId: string, password: string, dBpath: string) {

        userId = Buffer.from(userId).toString('base64');
        const keyPath: string = `${dBpath}${userId}.key`;
        dBpath = `${dBpath}${userId}.db`;
        this.IV = 16;

        // Since we chose aes-256-cbc with an IV,  our key
        // needs to be 256 bits (32 ASCII characters).
        // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
        if (fs.existsSync(`${keyPath}`)) {
            // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
            const encryptionBundle: Array<string | any> = fs.readFileSync(`${keyPath}`, 'ascii')
                .toString().split(':');
            this.encryptionKey = encryptionBundle.shift();
            this.userPasswordHash = encryptionBundle.join(':');

            // AUthenticate the user.
            if (! bcrypt.compareSync(`${password}${userId}`, this.userPasswordHash)) {
                throw new Error('Authentication failed');
            }
        } else {
            // We save the Store class supplied password, alongwith the encryption
            // key here.
            this.encryptionKey = this.generateKey();
            this.userPasswordHash = bcrypt.hashSync(`${password}${userId}`, saltRounds);
            // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
            fs.writeFileSync(`${keyPath}`, `${this.encryptionKey}:${this.userPasswordHash}`);
        }

        this.encryptionKeyPath = keyPath;

        this.adapter = new FileSync(dBpath,
            {
                serialize: (data: object) => this.encrypt(
                    JSON.stringify(data)),
                deserialize: (data: string) => JSON.parse(
                    this.decrypt(data))
            }
        );
        this.database = lowdb(this.adapter);
    }

    /**
     * The getter
     * @param key The property to be accessed
     */
    public async get(key: string) {
        return await this.database.get(key).value();
    }

    /**
     * The setter
     * @param key The property to be accessed
     * @param value The value of the accessed
     * property.
     */
    public async set(key: string, value: any) {
        try {
            await this.database.set(key, value)
                .write();
            return true;
        } catch (error) {
            throw new Error('Cant be accessed');
        }
    }

    /**
     * Remove a key's value and then write.
     * @param key The property to be accessed
     */
    public async remove(key: string) {
        await this.database.unset(key)
            .write();
    }

    // Generate a new store key
    private generateKey() {
        const r = Math.random;
        // tslint:disable-next-line: no-bitwise
        const fr = () => (r() * 36 | 0).toString(36);
        return [...Array(32)].map((_) => r() <= 0.5 ? fr().toUpperCase() : fr()).join('');
    }

    /**
     * To ensure the encrypted content never produces the same output,
     * we will use an Initialization Vector (IV) to add some randomness
     * to the encryption algorithm. For this to be strong, we need to
     * generate a unique random IV per encryption run – not a single
     * fixed pre-defined IV. This is similar to a salt for password
     * hashing, and will be stored with our encrypted data so we can
     * decrypt it later along with the key. In order to keep things
     * simple and still use a single database field and value for our
     * encrypted data, we will generate our IV before encryption, and
     * prepend it to the encrypted result. Then before decryption, will
     * read the IV we prepended to the encrypted result and use it along
     * with our key for decryption. This is very similar to how bcrypt
     * works.
     * @param text The information.
     */
    private encrypt(text: string) {
        const generateNewKey = Math.random() > 0.5 ? true : false;
        if (generateNewKey) {
            this.encryptionKey = this.generateKey();
            // tslint:disable-next-line: tsr-detect-non-literal-fs-filename
            fs.writeFileSync(`${this.encryptionKeyPath}`,
                `${this.encryptionKey}:${this.userPasswordHash}`);
        }

        // For AES, this is always 16
        const iv = crypto.randomBytes(this.IV);

        // Encrypt the message. Using the initialization vector
        const cipher = crypto.createCipheriv(
            'aes-256-cbc',
            Buffer.from(this.encryptionKey), iv);

        // The encrypted message
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat(
            [encrypted, cipher.final()]);

        // The iv and the encrypted information
        const encryptedInfo = iv.toString('hex') + ':'
            + encrypted.toString('hex');

        // Compress the information
        return zlib.deflateSync(encryptedInfo)
            .toString('base64');
    }

    /**
     * Decryption routine.
     * @param text The encrypted informaiton.
     */
    private decrypt(text: string) {
        // To base64
        const base64Buffer = Buffer.from(text, 'base64');

        // Uncompress (returns buffer)
        text = zlib.inflateSync(base64Buffer).toString();

        // Split to get the Initialization vector
        // and the information.
        const textParts: Array<string | any> = text.split(':');

        // the Initialization vector
        const iv = Buffer.from(textParts.shift(), 'hex');

        // the text
        const encryptedText = Buffer.from(textParts.join(':'),
            'hex');

        // The decipher
        const decipher = crypto.createDecipheriv('aes-256-cbc',
            Buffer.from(this.encryptionKey), iv);

        // The decrypted message.
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted.toString();
    }
}
