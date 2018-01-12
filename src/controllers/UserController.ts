import User, { UserType } from "../models/User";
import { Request, Response, NextFunction } from "express";
import * as passport from "passport";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import { check, validationResult, ValidationChain } from "express-validator/check";
import { matchedData, sanitize } from "express-validator/filter";

/**
 * POST /signup
 * Sign-up action
 */
export let postSignup = function(req: Request, res: Response, next: NextFunction) {

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
    User.findOne({email: req.body.email}, function(err: any, user: any) {
        if(err) {
            return res.status(500).json({message: "Failed finding user in DB", error: err});
        }
        if(user) {
            // email is already in use
            // TODO: give a flash message
            // return res.redirect("/signup");
            return res.status(409).json({message: "Email is already in use"});
        }
        console.log("It keeps going....");
        // make sure username isn't already in use
        User.findOne({username: req.body.username}, function(err: any, user: any) {
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
            User.schema.statics.createUser(newUser, function(err: any, user: any) {
                if(err) {
                    console.error("Failed creating user");
                    return res.status(500).json({message: "Failed creating user", error: err});
                } else {
                    console.log(user);
                    // TODO: log user in and send them to the home page
                    // res.redirect("../login");
                    res.status(200).json({message: "Success! Welcome " + newUser});
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
export let postLogin = function(req: Request, res: Response, next: NextFunction) {

    passport.authenticate("local", function(err: Error, user: UserType, info: any) {
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
        req.login(user, function(err) {
            if(err) {
                return next(err);
            }
            // Success! Redirect user & give them a web token
            // The payload contains all the data we want to be able to access locally that shouldn't change
            const payload = {
                "userID": user._id,
                "admin": user.admin
            };
            jwt.sign(payload, <string>process.env.TOKEN_SECRET, {expiresIn: 60*15, issuer: "Boz", subject: "AuthenticationToken"}, function(err, token) {
                if(err) {
                    return next(err);
                }
                // Persist token (store to localStorage and/or cookie on the front end)
                // All new requests should verify the web token
                // When token is valid, respond, otherwise send an error
                console.log("Token created!");
                User.findOne(user, function(err, doc) {
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