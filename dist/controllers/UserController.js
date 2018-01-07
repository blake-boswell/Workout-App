"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var User_1 = require("../models/User");
var passport = require("passport");
var jwt = require("jsonwebtoken");
/**
 * POST /signup
 * Sign-up action
 */
exports.postSignup = function (req, res, next) {
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
        console.log("It keeps going....");
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
            // hash pw with bcrypt
            var newUser = new User_1.default({
                username: req.body.username,
                displayName: req.body.displayName,
                password: req.body.password,
                email: req.body.email
            });
            // console.log(newUser);
            User_1.default.schema.statics.createUser(newUser, function (err, user) {
                if (err) {
                    console.error("Failed creating user");
                    return res.status(500).json({ message: "Failed creating user", error: err });
                }
                else {
                    console.log(user);
                    // TODO: log user in and send them to the home page
                    // res.redirect("../login");
                    res.status(200).json({ message: "Success! Welcome " + newUser });
                }
            });
        });
    });
};
/**
 * POST /login
 * Login action
 */
exports.postLogin = function (req, res, next) {
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
            // TODO: Flash user error message
            res.status(401).redirect("/login");
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
                User_1.default.findOne(user, function (err, doc) {
                    if (err) {
                        return next(err);
                    }
                    else if (doc) {
                        doc.accessToken = "Bearer " + token;
                        doc.save();
                    }
                    else {
                        return res.status(500).json({ message: "The user was not found. Couldn't provide the intended user with a token" });
                    }
                });
                // TODO: redirect to user homepage
                req.flash("AuthSuccess", "Successfully logged in!");
                return res.status(200).redirect("/");
            });
        });
    })(req, res, next);
};
