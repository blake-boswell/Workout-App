"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var jwt = require("jsonwebtoken");
var TokenGenerator = /** @class */ (function () {
    function TokenGenerator(secretOrPublicKey, secretOrPrivateKey, options) {
        this.secretOrPublicKey = secretOrPublicKey;
        this.secretOrPrivateKey = secretOrPrivateKey;
        this.options = options;
    }
    /**
     * Signing the token
     *
     * @param payload holds data for the payload of the JWT
     * @param signOptions for any options to pass on the JWT sign function
     */
    TokenGenerator.prototype.sign = function (payload, signOptions) {
        var jwtSignOptions = Object.assign({}, signOptions, this.options);
        jwt.sign(payload, this.secretOrPrivateKey, jwtSignOptions);
    };
    /**
     * Refreshing a token
     *
     * @param token is the token to be refreshed
     * @param refreshOptions has properties verify and jwtid
     * verify: holds the options you would use with the verify function
     * jwtid: holds the id for the new token
     */
    TokenGenerator.prototype.refresh = function (token, refreshOptions) {
        var payload = jwt.verify(token, this.secretOrPublicKey, refreshOptions.verify);
        console.log("Payload: ", payload);
        delete payload.iat;
        delete payload.exp;
        delete payload.nbf;
        delete payload.jti; // We are generating a new token, if you are using jwtid during signing, pass it in refreshOptions
        var jwtSignOptions = Object.assign({}, this.options, { jwtid: refreshOptions.jwtid });
        // The first signing converted all needed options into claims, they are already in the payload
        jwt.sign(payload, this.secretOrPrivateKey, jwtSignOptions);
    };
    return TokenGenerator;
}());
// const tokenGenerator: any = new TokenGenerator(SECRET, SECRET, {expiresIn: 60*15});
// const payload = {
//         "userName": user.userName,
//         "admin": user.admin
//     };
// const token = tokenGenerator.sign(payload, {issuer: "Boz", subject: "AuthenticationToken"});
// if(token) {
//     console.log("token created!");
// }
// // const tokenGenerator: any = new TokenGenerator(SECRET, SECRET, {expiresIn: 60*15});
// // const payload = {
// //         "userName": user.userName,
// //         "admin": user.admin
// //     };
// // const token = tokenGenerator.sign(payload, {issuer: "Boz", subject: "AuthenticationToken"});
// // if(token) {
// //     console.log("token created!");
// // }
// export default TokenGenerator;
