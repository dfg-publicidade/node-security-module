import { expect } from 'chai';
import crypto from 'crypto';
import { describe, it } from 'mocha';
import Security, { TokenSign } from '../src';

/* Tests */
describe('index.ts', (): void => {
    it('1. getToken / checkToken', async (): Promise<void> => {
        const key: string = '123456';
        const token: string = Security.getToken(key, {
            ref: {
                id: '123',
                other: 456
            }, since: new Date()
            // eslint-disable-next-line no-magic-numbers
        }, 60);

        expect(token).to.exist;

        const tokenSign: TokenSign = await Security.checkToken(token, key);

        expect(tokenSign).to.exist;
        expect(tokenSign.ref).to.exist;
        // eslint-disable-next-line no-magic-numbers
        expect(tokenSign.ref.id).to.be.eq('123');
        // eslint-disable-next-line no-magic-numbers
        expect(tokenSign.ref.other).to.be.eq(456);

        expect(tokenSign.since).to.exist;
        expect(tokenSign.iat).to.exist;
        expect(tokenSign.exp).to.exist;
        // eslint-disable-next-line no-magic-numbers
        expect(tokenSign.exp - tokenSign.iat).to.be.eq(60);
    });

    it('2. getToken / checkToken', async (): Promise<void> => {
        const key: string = '123456';
        // eslint-disable-next-line no-magic-numbers
        const token: string = Security.getToken(key, { ref: 123, since: new Date() });

        expect(token).to.exist;

        const tokenSign: TokenSign = await Security.checkToken(token, key);

        expect(tokenSign).to.exist;
        expect(tokenSign.ref).to.exist;
        // eslint-disable-next-line no-magic-numbers
        expect(tokenSign.ref).to.be.eq(123);

        expect(tokenSign.since).to.exist;
        expect(tokenSign.iat).to.exist;
    });

    it('3. getToken / checkToken', async (): Promise<void> => {
        const key: string = '123456';

        let tokenError: string;
        try {
            await Security.checkToken('invalid', key);
        }
        catch (error: any) {
            tokenError = error;
        }

        expect(tokenError).to.be.eq('INVALID_TOKEN');
    });

    it('4. getToken / checkToken', async (): Promise<void> => {
        const key: string = '123456';
        const token: string = Security.getToken(key, {});

        let tokenError: string;
        try {
            await Security.checkToken(token, key);
        }
        catch (error: any) {
            tokenError = error;
        }

        expect(tokenError).to.be.eq('INVALID_PAYLOAD');
    });

    it('5. testOpenAccess', async (): Promise<void> => {
        const openRoutes: any = [{
            regex: '^\\/$'
        }];

        expect(Security.testOpenAccess({
            uri: '/'
        } as any, undefined)).to.be.false;
        expect(Security.testOpenAccess({
            uri: '/test'
        } as any, openRoutes)).to.be.false;
        expect(Security.testOpenAccess({
            uri: '/'
        } as any, openRoutes)).to.be.true;
    });

    it('6. enPassword / checkPassword', async (): Promise<void> => {
        const hash: string = await Security.genPassword({
            saltRounds: 10
        }, '123456');

        expect(await Security.checkPassword('00000', hash)).to.be.false;
        expect(await Security.checkPassword('123456', hash)).to.be.true;
    });

    it('7. encodeId / isId / decodeId', async (): Promise<void> => {
        const config: any = {
            idEncodeKey: '123456',
            encodingLength: 10
        };

        const hash: string = await Security.encodeId(config, 1);

        expect(await Security.isId(config, hash)).to.be.true;
        expect(await Security.decodeId(config, hash)).to.be.eq(1);

        expect(await Security.isId(config, 'invalid id')).to.be.false;

        let tokenError: any;
        try {
            expect(await Security.decodeId(config, 'invalid id')).to.be.undefined;
        }
        catch (error: any) {
            tokenError = error;
        }

        expect(tokenError.message).to.contain('is invalid');

        expect(await Security.isId(config, 'other')).to.be.false;

        try {
            expect(await Security.decodeId(config, 'other')).to.be.undefined;
        }
        catch (error: any) {
            tokenError = error;
        }

        expect(tokenError.message).to.contain('is invalid');
    });

    it('8. encode / decode', async (): Promise<void> => {
        const config: any = {
            encodeKey: 'vOVH6sdmpNWjRRIqCc7rdxs01lwHzfr3'
        };

        // eslint-disable-next-line no-magic-numbers
        const iv: Buffer = crypto.randomBytes(16);

        const secret: string = Security.encode(config, iv, 'test');

        expect(Security.decode(config, iv, secret)).to.be.eq('test');
    });
});
