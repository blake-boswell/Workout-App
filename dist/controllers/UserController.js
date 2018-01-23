"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var User_1 = require("../models/User");
var passport = require("passport");
var jwt = require("jsonwebtoken");
var check_1 = require("express-validator/check");
var Mailgun = require("mailgun-js");
var crypto = require("crypto");
/**
 * POST /signup
 * Sign-up action
 */
exports.postSignup = function (req, res, next) {
    // form validation
    // Check for errors
    var errors = check_1.validationResult(req);
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
    User_1.default.findOne({ email: req.body.email }, function (err, user) {
        if (err) {
            return res.status(500).json({ message: "Failed finding user in DB", error: err });
        }
        if (user) {
            // email is already in use
            // TODO: give a flash message
            // return res.redirect("/signup");
            return res.status(409).json({ message: "Email is already in use" });
        }
        // make sure username isn't already in use
        User_1.default.findOne({ username: req.body.username }, function (err, user) {
            if (err) {
                console.error("Failed finding user in DB");
                return res.status(500).json({ message: "Failed finding user in DB", error: err });
            }
            if (user) {
                // username is already in use
                // TODO: give a flash message
                // return res.redirect("/signup");
                return res.status(409).json({ message: "Username is already in use" });
            }
            // email && username are unique
            // Create a verification token to email
            var verificationToken;
            crypto.randomBytes(20, function (err, buf) {
                if (err) {
                    req.session.sessionFlash = {
                        type: "Error",
                        message: "Error generating random token! " + err
                    };
                    res.status(500).redirect("/signup");
                }
                else if (buf) {
                    verificationToken = buf.toString("hex");
                    var newUser_1 = new User_1.default({
                        username: req.body.username,
                        displayName: req.body.displayName,
                        password: req.body.password,
                        email: req.body.email,
                        verificationToken: verificationToken
                    });
                    User_1.default.schema.statics.createUser(newUser_1, function (err, user) {
                        if (err) {
                            console.error("Failed creating user");
                            return res.status(500).json({ message: "Failed creating user", error: err });
                        }
                        else {
                            // console.log(user);
                            // TODO: log user in and send them to the home page
                            // res.redirect("../login");
                            var link = "http://" + req.get("host") + "/verify/" + verificationToken;
                            // Send verification email
                            exports.sendVerificationEmail(user.email, link, function (err, data) {
                                if (err) {
                                    req.session.sessionFlash = {
                                        type: "Error",
                                        message: "Error sending verification email! " + err
                                    };
                                    res.status(500).redirect("/signup");
                                }
                                req.session.sessionFlash = {
                                    type: "Success",
                                    message: "Success! Check your email for a verification link " + newUser_1.username
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
exports.signupValidation = [
    check_1.check("email").exists().withMessage("You must enter an email address.")
        .isEmail().withMessage("You must enter a valid email address.")
        .normalizeEmail(),
    check_1.check("password").exists().withMessage("You must enter a password.")
        .isLength({ min: 6 }).withMessage("Your password must be at least 6 characters long")
        .matches(/^(?=.*\d)(?=.*[A-Z])(?=.*[a-z]).+$/).withMessage("Your password must contain a number, a capital letter, and a lowercase letter."),
    check_1.check("confirmPassword").exists().withMessage("Please confirm your password")
        .custom(function (value, _a) {
        var req = _a.req;
        return value === req.body.password;
    }).withMessage("Your passwords do not match."),
    check_1.check("displayName").exists().withMessage("You must enter a display name.")
        .matches(/^[a-zA-Z0-9_-]*$/).withMessage("You may only use letters, numbers, and the symbols - and _."),
    check_1.check("username").exists().withMessage("You must enter a username.")
        .isAlphanumeric().withMessage("You may only use letters and numbers.")
];
/**
 * POST /login
 * Login action
 */
exports.postLogin = function (req, res, next) {
    User_1.default.findOne({ email: req.body.email }, function (err, user) {
        if (err) {
            return next(err);
        }
        if (!user) {
            req.session.sessionFlash = {
                type: "Error",
                message: "A user with that email does not exist."
            };
            return res.status(500).redirect("/login");
        }
        if (!user.isActive) {
            // Deny access
            req.session.sessionFlash = {
                type: "Error",
                message: "You must activate your account with the link sent to your email first."
            };
            return res.status(500).redirect("/login");
        }
        // User has activated account
        passport.authenticate("local", function (err, user, info) {
            // user and err are retrieved through the done callback from the LocalStrategy in /config/passport file
            if (info != undefined) {
                console.log("[Local Authenticate]You got some info: ");
                console.log(info);
            }
            if (err) {
                return next(err);
            }
            if (!user) {
                req.session.sessionFlash = {
                    type: "Error",
                    message: info
                };
                return res.status(401).redirect("/login");
            }
            // establish a session
            req.login(user, function (err) {
                if (err) {
                    return next(err);
                }
                // Success! Redirect user & give them a web token
                // The payload contains all the data we want to be able to access locally that shouldn't change
                var payload = {
                    "userID": user._id,
                    "admin": user.admin
                };
                jwt.sign(payload, process.env.TOKEN_SECRET, { expiresIn: 60 * 15, issuer: "Boz", subject: "AuthenticationToken" }, function (err, token) {
                    if (err) {
                        return next(err);
                    }
                    // Persist token (store to localStorage and/or cookie on the front end)
                    // All new requests should verify the web token
                    // When token is valid, respond, otherwise send an error
                    console.log("Token created!");
                    User_1.default.findOne(user, function (err, user) {
                        if (err) {
                            return next(err);
                        }
                        else if (user) {
                            user.accessToken = "Bearer " + token;
                            user.save();
                        }
                        else {
                            return res.status(500).json({ message: "The user was not found. Couldn't provide the intended user with a token" });
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
exports.postLogout = function (req, res) {
    // Log user out of session
    req.logout();
    res.redirect("/");
};
/**
 * Send verification email
 */
exports.sendVerificationEmail = function (receivers, link, callback) {
    var api_key = process.env.MAIL_API_KEY;
    var DOMAIN = process.env.MAIL_TEST_DOMAIN;
    var mailgun = new Mailgun({ apiKey: api_key, domain: DOMAIN });
    console.log(mailgun);
    var data = {
        from: "Bozzy <blake.w.boswell@gmail.com>",
        to: receivers,
        subject: "Hello",
        text: "Please click the following link to verify and activate your account\n" + link
    };
    mailgun.messages().send(data, function (err, body) {
        if (err) {
            console.log("FAILURE!\n" + err);
            callback(err, undefined);
        }
        else {
            console.log("SUCCESS!\n" + body);
            callback(undefined, body);
        }
    });
};
exports.verify = function (req, res) {
    User_1.default.findOne({ verificationToken: req.params.id }, function (err, user) {
        if (err) {
            return res.send(err);
        }
        if (!user.isActive) {
            user.isActive = true;
            user.verificationToken = undefined;
            console.log(user);
            user.save(function (err) {
                if (err) {
                    req.session.sessionFlash = {
                        type: "Error",
                        message: err
                    };
                    return res.status(401).redirect("/login");
                }
                console.log(user.username + " has been activated.");
                var html = "<h1>SUCCESS!</h1><br /><h3>" + user.username + ", you are now an active user!</h3>";
                return res.send(html);
            });
        }
        else {
            var html = "<h1>This user is already activated</h1>";
            console.log(user.username + " attempted to activate his/her account, but it has already been activated.");
            return res.send(html);
        }
    });
};
