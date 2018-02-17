/// <reference types="node" />
declare class TokenGenerator {
    secretOrPublicKey: string | Buffer;
    secretOrPrivateKey: string | Buffer;
    options: Object;
    constructor(secretOrPublicKey: string | Buffer, secretOrPrivateKey: string | Buffer, options: Object);
    /**
     * Signing the token
     *
     * @param payload holds data for the payload of the JWT
     * @param signOptions for any options to pass on the JWT sign function
     */
    sign(payload: Object, signOptions: Object): void;
    /**
     * Refreshing a token
     *
     * @param token is the token to be refreshed
     * @param refreshOptions has properties verify and jwtid
     * verify: holds the options you would use with the verify function
     * jwtid: holds the id for the new token
     */
    refresh(token: string, refreshOptions: Object): void;
}
export default TokenGenerator;
