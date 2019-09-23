"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const lowdb = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const crypto_1 = __importDefault(require("crypto"));
const zlib_1 = __importDefault(require("zlib"));
const fs_1 = __importDefault(require("fs"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const saltRounds = 10;
class ClientStoreDataBase {
    constructor(userId, password, dBpath) {
        userId = Buffer.from(userId).toString('base64');
        const keyPath = `${dBpath}${userId}.key`;
        dBpath = `${dBpath}${userId}.db`;
        this.IV = 16;
        if (fs_1.default.existsSync(`${keyPath}`)) {
            const encryptionBundle = fs_1.default.readFileSync(`${keyPath}`, 'ascii')
                .toString().split(':');
            this.encryptionKey = encryptionBundle.shift();
            this.userPasswordHash = encryptionBundle.join(':');
            if (!bcrypt_1.default.compareSync(`${password}${userId}`, this.userPasswordHash)) {
                throw new Error('Authentication failed');
            }
        }
        else {
            this.encryptionKey = this.generateKey();
            this.userPasswordHash = bcrypt_1.default.hashSync(`${password}${userId}`, saltRounds);
            fs_1.default.writeFileSync(`${keyPath}`, `${this.encryptionKey}:${this.userPasswordHash}`);
        }
        this.encryptionKeyPath = keyPath;
        this.adapter = new FileSync(dBpath, {
            serialize: (data) => this.encrypt(JSON.stringify(data)),
            deserialize: (data) => JSON.parse(this.decrypt(data))
        });
        this.database = lowdb(this.adapter);
    }
    get(key) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield this.database.get(key).value();
        });
    }
    set(key, value) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield this.database.set(key, value)
                    .write();
                return true;
            }
            catch (error) {
                throw new Error('Cant be accessed');
            }
        });
    }
    remove(key) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.database.unset(key)
                .write();
        });
    }
    generateKey() {
        const r = Math.random;
        const fr = () => (r() * 36 | 0).toString(36);
        return [...Array(32)].map((_) => r() <= 0.5 ? fr().toUpperCase() : fr()).join('');
    }
    encrypt(text) {
        const generateNewKey = Math.random() > 0.5 ? true : false;
        if (generateNewKey) {
            this.encryptionKey = this.generateKey();
            fs_1.default.writeFileSync(`${this.encryptionKeyPath}`, `${this.encryptionKey}:${this.userPasswordHash}`);
        }
        const iv = crypto_1.default.randomBytes(this.IV);
        const cipher = crypto_1.default.createCipheriv('aes-256-cbc', Buffer.from(this.encryptionKey), iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const encryptedInfo = iv.toString('hex') + ':'
            + encrypted.toString('hex');
        return zlib_1.default.deflateSync(encryptedInfo)
            .toString('base64');
    }
    decrypt(text) {
        const base64Buffer = Buffer.from(text, 'base64');
        text = zlib_1.default.inflateSync(base64Buffer).toString();
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto_1.default.createDecipheriv('aes-256-cbc', Buffer.from(this.encryptionKey), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    }
}
exports.ClientStoreDataBase = ClientStoreDataBase;
//# sourceMappingURL=Database.js.map