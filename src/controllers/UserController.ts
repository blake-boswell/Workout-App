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
 *
 * email
 * username
 * displayName
 * password
 */
export let postSignup = (req: Request, res: Response, next: NextFunction) => {

    // form validation
    // Check for errors
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
             // Create a verification token to email
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
                    const newUser = new User({
                        username: req.body.username,
                        displayName: req.body.displayName,
                        password: req.body.password,
                        email: req.body.email,
                        verificationToken: verificationToken
                    });
                    newUser.save(function(err) {
                        if(err) {
                            console.error("Failed creating user");
                            return res.status(500).json({message: "Failed creating user", error: err});
                        }
                        // console.log(user);
                        // TODO: log user in and send them to the home page
                        // res.redirect("../login");
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
 *
 * email
 * password
 */
export let postLogin = (req: Request, res: Response, next: NextFunction) => {
    User.findOne({email: req.body.email}, (err, user) => {
        if(err) {
            return next(err);
        }

        if(!user) {
            req.session.sessionFlash = {
                type: "Error",
                message: "A user with that email does not exist."
            };
            return res.status(500).redirect("/login");
        }

        if(!user.isActive) {
            // Deny access
            req.session.sessionFlash = {
                type: "Error",
                message: "You must activate your account with the link sent to your email first."
            };
            return res.status(500).redirect("/login");
        }

        // User has activated account
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
                    User.findOne(user, (err, user) => {
                        if(err) {
                            return next(err);
                        } else if(user) {
                            user.accessToken = "Bearer " + token;
                            user.save();
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
    });
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
 * GET /forgot/
 * @param req Request Object
 * @param res Response Object
 */
export let getForgotPassword = (req: Request, res: Response) => {
    res.send({message: "Forgot Password Page!"});
};

/**
 * POST /forgot
 * Forgot password action
 */
export let postForgotPassword = (req: Request, res: Response) => {
    // Generate JWT
    const userEmail = req.body.email;
    User.findOne({ email: userEmail }, (err, user) => {
        const payload = { "userID": user._id };
        const options = {
            expiresIn: 60*15, // 15 minutes
            issuer: "Boz",
            subject: "Forgot Password"
        };
        // Append JWT to email
        jwt.sign(payload, process.env.TOKEN_SECRET, options, (err, token) => {
            // error handler
            if(err)
                return errorHandler(req, res, 500, err, "forgot");
            const link = "http://" + req.get("host") + "/update/password/" + token;
            // Set the token on the user for verification (want to know if it is this specific user)
            // user.resetToken = token;
            // user.save();
            // Send email
            forgotPasswordEmail(userEmail, link, (err) => {
                if(err)
                    return errorHandler(req, res, 500, err, "forgot");
                return res.send({ message: "Email sent!" });
            });
        });
    });
};

/**
 * POST action /update/password/:token
 * @param req Request Object
 * @param res Response Object
 */
export let postChangePasswordAction = (req: Request, res: Response) => {
    // Grab token
    const key = req.params.token;
    // Decode the token
    jwt.verify(key, process.env.TOKEN_SECRET, (err, decoded) => {
        if(err)
            return errorHandler(req, res, 500, err);
        console.log("Decoded Payload", decoded);
        // Find user by ID
        User.findById(decoded.userID, (err: any, user: UserType) => {
            if(err)
                return errorHandler(req, res, 404, err, "404");
            // Update Password
            console.log("Updating PW..");
            user.password = req.body.newPassword;
            user.save(function(err) {
                if(err)
                    return errorHandler(req, res, 500, err);
                decoded.expiresIn = 0;
                return res.send({message: "Password successfully updated!"});
            });
        });
    });
};

export let getChangePassword = (req: Request, res: Response) => {

};

export let generatePasswordUpdatePage = (req: Request, res: Response) => {
    // Generate the Password Update Form
    // res.sendFile("updatePassword");
};

/**
 * Send email
 * @param to who the email is sent to
 * @param subject the subject of the email
 * @param message the contents of the email
 * @param callback callback with the parameters error and data
 */
export let sendEmail = (to: String, subject: String, message: string, callback: any) => {
    const api_key = process.env.MAIL_API_KEY;
    const DOMAIN = process.env.MAIL_TEST_DOMAIN;
    const mailgun = new Mailgun({apiKey: api_key, domain: DOMAIN});

    console.log(mailgun);
    const data = {
      from: "Bozzy <blake.w.boswell@gmail.com>",
      to: to,
      subject: subject,
      text: message
    };

    mailgun.messages().send(data, (err, body) => {
        if(err) {
            console.log("FAILURE!\n" + err);
            callback(err, undefined);
        } else {
            console.log("SUCCESS!\n" + body);
            callback(undefined, body);
        }
    });
};

/**
 * Send verification email
 * @param receiver who the email is sent to
 * @param link email link to verify account
 * @param callback callback with the parameters error and data
 */
export let sendVerificationEmail = (receiver: String, link: String, callback: any) => {
    const to = receiver;
    const subject = "Verify Email";
    const message = "Please click the following link to verify and activate your account\n" + link;

    sendEmail(to, subject, message, callback);
};

/**
 * Send forgot password email link
 * @param receiver who the email is sent to
 * @param link email link to verify account
 * @param callback callback with the parameters error and data
 */
export let forgotPasswordEmail = (receiver: String, link: String, callback: any) => {
    const to = receiver;
    const subject = "Forgot Password";
    const message = "Please click on the following link to change your password\n" + link;

    sendEmail(to, subject, message, callback);
};

export let verify = (req: Request, res: Response) => {
    User.findOne({verificationToken: req.params.id}, (err, user) => {
        if(err) {
            return res.send(err);
        }
        if(!user.isActive) {
            user.isActive = true;
            user.verificationToken = undefined;
            console.log(user);
            user.save((err) => {
                if(err) {
                    req.session.sessionFlash = {
                        type: "Error",
                        message: err
                    };
                    return res.status(401).redirect("/login");
                }
                console.log(user.username + " has been activated.");
                const html = "<h1>SUCCESS!</h1><br /><h3>" + user.username + ", you are now an active user!</h3>";
                return res.send(html);
            });
        } else {
            const html = "<h1>This user is already activated</h1>";
            console.log(user.username + " attempted to activate his/her account, but it has already been activated.");
            return res.send(html);
        }
    });
};

const errorHandler = (req: Request, res: Response, statusCode: number, err: Error, redirectPage?: String) => {
    req.session.sessionFlash = {
        type: "Error",
        message: err
    };
    if(redirectPage) {
        res.status(statusCode).redirect("/" + redirectPage);
    }
    console.log("Error in errorHandler\nError: ", err);
};