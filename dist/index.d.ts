import { Request } from 'express';
import TokenSign from './interfaces/tokenSign';
declare class Security {
    static getToken(key: string, content: any, exp?: string | number): string;
    static checkToken(token: string, key: string): Promise<TokenSign>;
    static testOpenAccess(req: Request, openRoutes: any): boolean;
    static genPassword(config: any, passwd: string): Promise<string>;
    static genPasswordSync(config: any, passwd: string): string;
    static checkPassword(passwd: string, hash: string): Promise<boolean>;
    static checkPasswordSync(passwd: string, hash: string): boolean;
    static encodeId(config: any, id: number): string;
    static decodeId(config: any, id: string): number;
}
export default Security;
