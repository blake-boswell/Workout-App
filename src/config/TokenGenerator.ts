// import * as jwt from "jsonwebtoken";

// class TokenGenerator {
//     secretOrPublicKey: any;
//     secretOrPrivateKey: any;
//     options: Object;

//     constructor(secretOrPublicKey: any, secretOrPrivateKey: any, options: Object) {
//         this.secretOrPublicKey = secretOrPublicKey;
//         this.secretOrPrivateKey = secretOrPrivateKey;
//         this.options = options;
//     }

//     /**
//      * Signing the token
//      *
//      * @param payload holds data for the payload of the JWT
//      * @param signOptions for any options to pass on the JWT sign function
//      */
//     sign(payload: Object, signOptions: Object): any {
//         const jwtSignOptions = (<any>Object).assign({}, signOptions, this.options);
//         return jwt.sign(payload, this.secretOrPrivateKey, jwtSignOptions);
//     }

//     /**
//      * Refreshing a token
//      *
//      * @param token is the token to be refreshed
//      * @param refreshOptions has properties verify and jwtid
//      * verify: holds the options you would use with the verify function
//      * jwtid: holds the id for the new token
//      */
//     refresh(token: any, refreshOptions: Object): any {
//         const payload = jwt.verify(token, this.secretOrPublicKey, refreshOptions.verify);
//         delete payload.iat;
//         delete payload.exp;
//         delete payload.nbf;
//         delete payload.jti; // We are generating a new token, if you are using jwtid during signing, pass it in refreshOptions
//         const jwtSignOptions = (<any>Object).assign({ }, this.options, { jwtid: refreshOptions.jwtid });
//         // The first signing converted all needed options into claims, they are already in the payload
//         return jwt.sign(payload, this.secretOrPrivateKey, jwtSignOptions);
//     }
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