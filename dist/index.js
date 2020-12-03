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
const bcryptjs_1 = __importDefault(require("bcryptjs"));
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
    static checkToken(token, key) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                jsonwebtoken_1.default.verify(token, key, (err, decoded) => {
                    if (err) {
                        const invalidToken = 'INVALID_TOKEN';
                        reject(invalidToken);
                    }
                    else {
                        if (!decoded || !decoded.ref || !decoded.since) {
                            const invalidPayload = 'INVALID_PAYLOAD';
                            reject(invalidPayload);
                        }
                        else {
                            resolve(decoded);
                        }
                    }
                });
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
    static genPassword(config, passwd) {
        return __awaiter(this, void 0, void 0, function* () {
            return bcryptjs_1.default.hash(passwd, config.security.saltRounds);
        });
    }
    static genPasswordSync(config, passwd) {
        return bcryptjs_1.default.hashSync(passwd, config.security.saltRounds);
    }
    static checkPassword(passwd, hash) {
        return __awaiter(this, void 0, void 0, function* () {
            return bcryptjs_1.default.compare(passwd, hash);
        });
    }
    static checkPasswordSync(passwd, hash) {
        return bcryptjs_1.default.compareSync(passwd, hash);
    }
    static encodeId(config, id) {
        return new hashids_1.default(config.security.idEncodeKey, config.security.encodingLength).encode(id);
    }
    static decodeId(config, id) {
        return new hashids_1.default(config.security.idEncodeKey, config.security.encodingLength).decode(id)[0];
    }
}
exports.default = Security;
