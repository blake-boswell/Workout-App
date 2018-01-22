import User, { UserType } from "../models/User";
import { Request, Response, NextFunction } from "express";
import * as passport from "passport";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import { check, validationResult, ValidationChain } from "express-validator/check";
import { matchedData, sanitize } from "express-validator/filter";
import * as nodemailer from "nodemailer";
import * as Mailgun from "mailgun-js";
import * as crypto from "crypto";


/**
 * POST /signup
 * Sign-up action
 */
export let postSignup = (req: Request, res: Response, next: NextFunction) => {

    // form validation

    const errors = validationResult(req);
    console.log(errors.mapped());
    if (!errors.isEmpty()) {
        console.log("We got some errors for you boss!");
        req.session.sessionFlash = {
            type: "Error",
            message: errors.mapped()
        };
        return res.status(500).redirect("/signup");
    }

    // make sure the email isn't already in use
    User.findOne({email: req.body.email}, (err: any, user: any) => {
        if(err) {
            return res.status(500).json({message: "Failed finding user in DB", error: err});
        }
        if(user) {
            // email is already in use
            // TODO: give a flash message
            // return res.redirect("/signup");
            return res.status(409).json({message: "Email is already in use"});
        }

        // make sure username isn't already in use
        User.findOne({username: req.body.username}, (err: any, user: any) => {
            if(err) {
                console.error("Failed finding user in DB");
                return res.status(500).json({message: "Failed finding user in DB", error: err});
            }
            if(user) {
                // username is already in use
                // TODO: give a flash message
                // return res.redirect("/signup");
                return res.status(409).json({message: "Username is already in use"});
            }
            // email && username are unique
            // hash pw with bcrypt
            const newUser = new User({
                username: req.body.username,
                displayName: req.body.displayName,
                password: req.body.password,
                email: req.body.email
            });
            // console.log(newUser);
            User.schema.statics.createUser(newUser, (err: any, user: any) => {
                if(err) {
                    console.error("Failed creating user");
                    return res.status(500).json({message: "Failed creating user", error: err});
                } else {
                    // console.log(user);
                    // TODO: log user in and send them to the home page
                    // res.redirect("../login");
                    // Create a verification token
                    let verificationToken: String;
                    crypto.randomBytes(20, (err, buf) => {
                        if(err) {
                            req.session.sessionFlash = {
                                type: "Error",
                                message: "Error generating random token! " + err
                            };
                            res.status(500).redirect("/signup");
                        } else if(buf) {
                            verificationToken = buf.toString("hex");
                            user.verificationToken = verificationToken;
                            user.save();
                            const link = "http://" + req.get("host") + "/verify/" + verificationToken;
                            // Send verification email
                            sendVerificationEmail(user.email, link, (err: any, data: any) => {
                                if(err) {
                                    req.session.sessionFlash = {
                                        type: "Error",
                                        message: "Error sending verification email! " + err
                                    };
                                    res.status(500).redirect("/signup");
                                }
                                req.session.sessionFlash = {
                                    type: "Success",
                                    message: "Success! Check your email for a verification link " + newUser.username
                                };
                                res.status(200).redirect("/login");
                            });
                        }
                    });
                }
            });
        });
    });
};

/**
 * POST /signup
 * Validation Middleware
 */
export let signupValidation: ValidationChain [] = [
    check("email").exists().withMessage("You must enter an email address.")
        .isEmail().withMessage("You must enter a valid email address.")
        .normalizeEmail(),
    check("password").exists().withMessage("You must enter a password.")
        .isLength({ min: 6 }).withMessage("Your password must be at least 6 characters long")
        .matches(/^(?=.*\d)(?=.*[A-Z])(?=.*[a-z]).+$/).withMessage("Your password must contain a number, a capital letter, and a lowercase letter."),
    check("confirmPassword").exists().withMessage("Please confirm your password")
        .custom((value, { req }) => value === req.body.password).withMessage("Your passwords do not match."),
    check("displayName").exists().withMessage("You must enter a display name.")
        .matches(/^[a-zA-Z0-9_-]*$/).withMessage("You may only use letters, numbers, and the symbols - and _."),
    check("username").exists().withMessage("You must enter a username.")
        .isAlphanumeric().withMessage("You may only use letters and numbers.")
];

/**
 * POST /login
 * Login action
 */
export let postLogin = (req: Request, res: Response, next: NextFunction) => {

    passport.authenticate("local", (err: Error, user: UserType, info: any) => {
        // user and err are retrieved through the done callback from the LocalStrategy in /config/passport file
        if(info != undefined) {
            console.log("[Local Authenticate]You got some info: ");
            console.log(info);
        }
        if(err) {
            return next(err);
        }
        if(!user) {
            // TODO: Flash user error message
            req.session.sessionFlash = {
                type: "Error",
                message: info
            };
            return res.status(401).redirect("/login");
        }
        // establish a session
        req.login(user, (err) => {
            if(err) {
                return next(err);
            }
            // Success! Redirect user & give them a web token
            // The payload contains all the data we want to be able to access locally that shouldn't change
            const payload = {
                "userID": user._id,
                "admin": user.admin
            };
            jwt.sign(payload, <string>process.env.TOKEN_SECRET, {expiresIn: 60*15, issuer: "Boz", subject: "AuthenticationToken"}, (err, token) => {
                if(err) {
                    return next(err);
                }
                // Persist token (store to localStorage and/or cookie on the front end)
                // All new requests should verify the web token
                // When token is valid, respond, otherwise send an error
                console.log("Token created!");
                User.findOne(user, (err, doc) => {
                    if(err) {
                        return next(err);
                    } else if(doc) {
                        doc.accessToken = "Bearer " + token;
                        doc.save();
                    } else {
                        return res.status(500).json({message: "The user was not found. Couldn't provide the intended user with a token"});
                    }
                });
                // redirect to user homepage
                req.session.sessionFlash = {
                    type: "Success",
                    message: "Successfully logged in!"
                };
                return res.status(200).redirect("/");
            });
        });
    })(req, res, next);
};

/**
 * POST /logout
 * Logout action
 */
export let postLogout = (req: Request, res: Response) => {
    // Log user out of session
    req.logout();
    res.redirect("/");
};

/**
 * Send verification email
 */
export let sendVerificationEmail = (receivers: String, link: String, callback: any) => {
    // Generate test SMTP service account from ethereal.email
    // Only needed if you don't have a real mail account for testing
    // nodemailer.createTestAccount((err, account) => {
    //     // create reusable transporter object using the default SMTP transport
    //     console.log("Account: ", account);
    //     const transporter = nodemailer.createTransport({
    //         host: "smtp.gmail.com",
    //         port: 465,
    //         secure: true, // true for 465, false for other ports
    //         auth: {
    //             user: "bozzy.test.service@gmail.com",
    //             pass: process.env.EMAIL_PW
    //         }
    //     });

    //     // setup email data with unicode symbols
    //     const mailOptions = {
    //         from: "\"Bozzy B 👻\" <bozzy.test.service@gmail.com>", // sender address
    //         to: receivers, // list of receivers
    //         subject: "Hello ✔", // Subject line
    //         text: "Hello world?", // plain text body
    //         html: "<b>Hello world?</b>" // html body
    //     };

    //     // send mail with defined transport object
    //     transporter.sendMail(mailOptions, (error, info) => {
    //         if (error) {
    //             return console.log(error);
    //         }
    //         console.log("Message sent: %s", info.messageId);
    //         // Preview only available when sending through an Ethereal account
    //         console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));

    //         // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@blurdybloop.com>
    //         // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
    //     });
    // });

   // var mailgun = require("mailgun-js");
    const api_key = process.env.MAIL_API_KEY;
    const DOMAIN = process.env.MAIL_TEST_DOMAIN;
    // var mailgun = require('mailgun-js')({apiKey: api_key, domain: DOMAIN});
    const mailgun = new Mailgun({apiKey: api_key, domain: DOMAIN});

    console.log(mailgun);
    const data = {
      from: "Bozzy <blake.w.boswell@gmail.com>",
      to: receivers,
      subject: "Hello",
      text: "Please click the following link to verify and activate your account\n" + link
    };

    mailgun.messages().send(data, function (err, body) {
        if(err) {
            console.log("FAILURE!\n" + err);
            callback(err, undefined);
        } else {
            console.log("SUCCESS!\n" + body);
            callback(undefined, body);
        }
    });
};

export let verify = (req: Request, res: Response) => {
    User.findOne({verificationToken: req.params.id}, (err, user) => {
        if(err) {
            return res.send(err);
        }
        if(!user.isActive) {
            user.isActive = true;
            user.verificationToken = undefined;
            user.save();
            const html = "<h1>SUCCESS!</h1><br /><h3>" + user.username + ", you are now an active user!</h3>";
            return res.send(html);
        }
        const html = "<h1>This user is already activated</h1>";
        return res.send(html);
    });
};