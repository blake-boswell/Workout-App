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
             generateRandomString((err, token) => {
                if(err) {
                    const errorMsg = new Error("Error generating random token! " + err);
                    return errorHandler(req, res, 500, errorMsg, "signup");
                }
                if(token) {
                    const newUser = new User({
                        username: req.body.username,
                        displayName: req.body.displayName,
                        password: req.body.password,
                        email: req.body.email,
                        verificationToken: token
                    });
                    newUser.save(function(err) {
                        if(err) {
                            console.error("Failed creating user");
                            return res.status(500).json({message: "Failed creating user", error: err});
                        }
                        // console.log(user);
                        // TODO: log user in and send them to the home page
                        // res.redirect("../login");
                        const link = "http://" + req.get("host") + "/verify/" + token;
                        // Send verification email
                        sendVerificationEmail(user.email, link, (err: any, data: any) => {
                            if(err) {
                                const errorMsg = new Error("Error sending verification email! " + err);
                                return errorHandler(req, res, 500, errorMsg, "signup");
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
 * @param req Request object
 * @param res Response object
 * @param next Next object
 */
export let postLogin = (req: Request, res: Response, next: NextFunction) => {
    User.findOne({email: req.body.email}, (err, user) => {
        if(err) {
            return next(err);
        }

        if(!user) {
            const errorMsg = new Error("A user with that email does not exist.");
            return errorHandler(req, res, 404, errorMsg, "login");
        }

        if(!user.isActive) {
            // Deny access
            const errorMsg = new Error("You must activate your account with the link sent to your email first.");
            return errorHandler(req, res, 500, errorMsg, "login");
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
                return errorHandler(req, res, 401, info, "login");
            }
            // establish a session
            req.login(user, (err) => {
                if(err) {
                    return next(err);
                }
                if(user) {
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
                }
            });
        })(req, res, next);
    });
};

/**
 * POST /logout
 * Logout action
 * @param req Request object
 * @param res Response object
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
 * 
 * email
 * Forgot password action
 * @param req Request object
 * @param res Response object
 */
export let postForgotPassword = (req: Request, res: Response) => {
    // Generate JWT
    const userEmail = req.body.email;
    User.findOne({ email: userEmail }, (err, user) => {
        // Append JWT to email
        generateRandomString((err, token) => {
            if(err)
                return errorHandler(req, res, 500, err, "forgot");
            if(user) {
                const link = "http://" + req.get("host") + "/update/password/" + token;
                // Set the token on the user for verification
                user.resetToken = token;
                user.save((err) => {
                    if(err)
                        return errorHandler(req, res, 500, err, "forgot");
                    // Send email
                    forgotPasswordEmail(userEmail, link, (err) => {
                        if(err)
                            return errorHandler(req, res, 500, err, "forgot");
                        return res.send({ message: "Email sent!" });
                    });
                });
            } else {
                const err = new Error("Could not find a user with that email address");
                return errorHandler(req, res, 404, err, "forgot");
            }
        });
    });
};

/**
 * POST action /update/password/:token
 * @param req Request Object
 * @param res Response Object
 */
export let postChangePassword = (req: Request, res: Response) => {
    // Grab token
    const token = req.params.token;
    // Find user by token
    User.findOne({ resetToken: token }, (err: any, user: UserType) => {
        if(err)
            return errorHandler(req, res, 404, err, "404");
        if(user) {
            // Update Password
            console.log("Updating PW..");
            user.password = req.body.newPassword;
            // Remove token
            user.resetToken = undefined;
            user.save(function(err) {
                if(err)
                    return errorHandler(req, res, 500, err);
                return res.send({message: "Password successfully updated!"});
            });
        } else {
            // Redirect to 404 page
            return res.send({ message: "404 Page Not Found." });
        }
    });
};

export let generatePasswordUpdatePage = (req: Request, res: Response) => {
    // Generate the Password Update Form
    // res.sendFile("updatePassword");
    res.send({message: "Update PW Page"});
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

/**
 * Verify and activate user account
 * @param req Request object
 * @param res Response object
 */
export let verify = (req: Request, res: Response) => {
    User.findOne({verificationToken: req.params.id}, (err, user) => {
        if(err) {
            return res.send(err);
        }
        if(!user) {
            const err = new Error("User not found.");
            return errorHandler(req, res, 404, err, );
        }
        if(!user.isActive) {
            user.isActive = true;
            user.verificationToken = undefined;
            console.log(user);
            user.save((err) => {
                if(err) {
                    return errorHandler(req, res, 401, err, "login");
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

/**
 * Creates an error flash message and optionally redirects the user
 * @param req Request object
 * @param res Response object
 * @param statusCode HTTP status code
 * @param err Error object to be used as the message
 * @param redirectPage Page to redirect to (optional)
 */
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

/**
 * Generates a random string to be appended as a token to routes
 * EX: 5c355a1730cbf8487757a7f6451d020659f8f4c1
 * @param callback Callback function containing the err and token
 */
const generateRandomString = (callback) => {
    crypto.randomBytes(20, (err, buf) => {
        if(err)
            return callback(err);
        if(buf) {
            const token = buf.toString("hex");
            return callback(undefined, token);
        }
    });
};