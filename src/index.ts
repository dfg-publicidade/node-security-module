import bcrypt from 'bcryptjs';
import { Request } from 'express';
import Hashids from 'hashids';
import jwt from 'jsonwebtoken';
import { ObjectId } from 'mongodb';
import AccessStatus from './enums/accessStatus';
import TokenSign from './interfaces/tokenSign';

/* Module */
class Security {
    public static getToken(key: string, content: any, exp?: string | number): string {
        const payload: any = content;

        const options: jwt.SignOptions = {};

        if (exp) {
            options.expiresIn = exp;
        }

        return jwt.sign(payload, key, options);
    }

    public static async checkToken(token: string, key: string): Promise<TokenSign> {
        return new Promise<TokenSign>((
            resolve: (tokenSign: TokenSign) => void,
            reject: (status: AccessStatus) => void
        ): void => {
            jwt.verify(token, key, (err: any, decoded: TokenSign): void => {
                if (err) {
                    const invalidToken: AccessStatus = 'INVALID_TOKEN';
                    reject(invalidToken);
                }
                else {
                    if (!decoded || !decoded.ref || !decoded.since) {
                        const invalidPayload: AccessStatus = 'INVALID_PAYLOAD';
                        reject(invalidPayload);
                    }
                    else {
                        resolve(decoded);
                    }
                }
            });
        });
    }

    public static testOpenAccess(req: Request, openRoutes: any[]): boolean {
        if (openRoutes) {
            let actionItem: {
                _id: ObjectId;
                name: string;
                uri: string;
                regex: string;
            };

            const uri: string = req.uri;

            for (actionItem of openRoutes) {
                if (actionItem.regex && uri && new RegExp(actionItem.regex).test(uri)) {
                    return true;
                }
            }
        }

        return false;
    }

    public static async genPassword(config: any, passwd: string): Promise<string> {
        return bcrypt.hash(passwd, config.saltRounds);
    }

    public static async checkPassword(passwd: string, hash: string): Promise<boolean> {
        return bcrypt.compare(passwd, hash);
    }

    public static encodeId(config: any, id: number): string {
        return new Hashids(config.idEncodeKey, config.encodingLength).encode(id);
    }

    public static decodeId(config: any, id: string): number {
        try {
            return new Hashids(config.idEncodeKey, config.encodingLength).decode(id)[0] as number;
        }
        catch (error: any) {
            // eslint-disable-next-line no-console
            console.error(error);
            return undefined;
        }
    }

    public static isId(config: any, id: string): boolean {
        return new Hashids(config.idEncodeKey, config.encodingLength).isValidId(id);
    }
}

export default Security;
export { AccessStatus, TokenSign };
