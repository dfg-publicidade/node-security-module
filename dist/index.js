"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const crypto_1 = __importDefault(require("crypto"));
const hashids_1 = __importDefault(require("hashids"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
/* Module */
class Security {
    static getToken(key, content, exp) {
        const payload = content;
        const options = {};
        if (exp) {
            options.expiresIn = exp;
        }
        return jsonwebtoken_1.default.sign(payload, key, options);
    }
    static async checkToken(token, key) {
        return new Promise((resolve, reject) => {
            jsonwebtoken_1.default.verify(token, key, (err, decoded) => {
                if (err) {
                    const invalidToken = 'INVALID_TOKEN';
                    reject(invalidToken);
                }
                else {
                    if (!decoded || !decoded.payload || !decoded.since) {
                        const invalidPayload = 'INVALID_PAYLOAD';
                        reject(invalidPayload);
                    }
                    else {
                        resolve(decoded);
                    }
                }
            });
        });
    }
    static testOpenAccess(req, openRoutes) {
        if (openRoutes) {
            let actionItem;
            const uri = req.uri;
            for (actionItem of openRoutes) {
                if (actionItem.regex && uri && new RegExp(actionItem.regex).test(uri)) {
                    return true;
                }
            }
        }
        return false;
    }
    static async genPassword(config, passwd) {
        return bcryptjs_1.default.hash(passwd, config.saltRounds);
    }
    static async checkPassword(passwd, hash) {
        return bcryptjs_1.default.compare(passwd, hash);
    }
    static encodeId(config, id) {
        return new hashids_1.default(config.idEncodeKey, config.encodingLength).encode(id);
    }
    static decodeId(config, id) {
        const value = new hashids_1.default(config.idEncodeKey, config.encodingLength).decode(id)[0];
        if (!value) {
            throw new Error(`The provided ID (${id}) is invalid`);
        }
        return value;
    }
    static encode(config, iv, value) {
        const cipher = crypto_1.default.createCipheriv('aes-256-cbc', config.encodeKey, iv);
        return Buffer.concat([cipher.update(value), cipher.final()]).toString('hex');
    }
    static decode(config, iv, value) {
        const decipher = crypto_1.default.createDecipheriv('aes-256-cbc', config.encodeKey, iv);
        return Buffer.concat([decipher.update(value, 'hex'), decipher.final()]).toString();
    }
    static isId(config, id) {
        const hashids = new hashids_1.default(config.idEncodeKey, config.encodingLength);
        if (hashids.isValidId(id)) {
            return hashids.decode(id).length > 0;
        }
        return false;
    }
}
exports.default = Security;
