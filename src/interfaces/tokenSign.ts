interface TokenSign {
    ref: string;
    since: Date | number;
    iat: number;
    exp: number;
}

export default TokenSign;
