interface TokenSign {
    payload: any;
    since: Date | number;
    iat: number;
    exp: number;
}
export default TokenSign;
