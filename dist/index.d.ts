/// <reference types="node" />
import { Request } from 'express';
import AccessStatus from './enums/accessStatus';
import TokenSign from './interfaces/tokenSign';
declare class Security {
    static getToken(key: string, content: any, exp?: string | number): string;
    static checkToken(token: string, key: string): Promise<TokenSign>;
    static testOpenAccess(req: Request, openRoutes: any[]): boolean;
    static genPassword(config: any, passwd: string): Promise<string>;
    static checkPassword(passwd: string, hash: string): Promise<boolean>;
    static encodeId(config: any, id: number): string;
    static decodeId(config: any, id: string): number;
    static encode(config: any, iv: Buffer, value: string): string;
    static decode(config: any, iv: Buffer, value: string): string;
    static isId(config: any, id: string): boolean;
}
export default Security;
export { AccessStatus, TokenSign };
