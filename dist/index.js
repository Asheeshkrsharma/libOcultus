"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const SignalProtocolManager_1 = __importDefault(require("./SignalProtocolManager"));
const SignalClientStore_1 = require("./SignalClientStore");
const privates = new WeakMap();
class Occultus {
    constructor(userId, password, SSS, clientStorePath) {
        this.status = false;
        privates.set(this, {
            _SPMPrivate: new SignalProtocolManager_1.default(userId, SSS, new SignalClientStore_1.SignalClientStore(userId, password, clientStorePath))
        });
        this.status = false;
    }
    init() {
        return __awaiter(this, void 0, void 0, function* () {
            yield privates.get(this)._SPMPrivate.initializeAsync();
            this.status = true;
        });
    }
    encrypt(userId, message) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield privates.get(this)
                ._SPMPrivate.encryptMessageAsync(userId, message);
        });
    }
    decrypt(userId, cypher) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield privates.get(this)
                ._SPMPrivate.decryptMessageAsync(userId, cypher);
        });
    }
    ;
}
exports.Occultus = Occultus;
//# sourceMappingURL=index.js.map