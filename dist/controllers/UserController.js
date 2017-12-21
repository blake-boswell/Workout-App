"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var User_1 = require("../models/User");
var bcrypt = require("bcrypt");
/**
 * POST /signup
 * Sign-up action
 */
exports.postSignup = function (req, res, next) {
    // make sure the email isn't already in use
    User_1.default.findOne({ email: req.body.email }, function (err, user) {
        if (err) {
            return next(err);
        }
        if (user) {
            // email is already in use
            // give a flash message
            return res.redirect("/signup");
        }
        // make sure username isn't already in use
        User_1.default.findOne({ userName: req.body.userName }, function (err, user) {
            if (err) {
                return next(err);
            }
            if (user) {
                // username is already in use
                // give a flash message
                return res.redirect("/signup");
            }
        });
        // email is unique
        // hash pw with bcrypt
        bcrypt.genSalt(10, function (err, salt) {
            if (err) {
                console.error("Failed generating salt.");
                next(err);
            }
            bcrypt.hash(req.body.password, salt, function (err, hash) {
                if (err) {
                    console.error("Could not hash password");
                    next(err);
                }
                var newUser = new User_1.default({
                    userName: req.body.userName,
                    password: hash,
                    email: req.body.email
                });
                newUser.save(function (err) {
                    if (err) {
                        return next(err);
                    }
                }).then(function () {
                    // log user in and send them to the home page
                    // res.redirect("../login");
                    res.send("Success!" + newUser);
                });
            });
        });
    });
};
/**
 * POST /login
 * Login action
 */
exports.postLogin = function (req, res, next) {
    // is information correct
    User_1.default.findOne({ userName: req.body.userName }, function (err, user) {
        if (err) {
            return next(err);
        }
        console.log("user:");
        console.log(user);
        if (user) {
            // compare pw to DB pw
            bcrypt.compare(req.body.password, user.password, function (err, response) {
                if (err) {
                    return next(err);
                }
                if (response) {
                    // Success! Log user in & give them a web token
                    res.status(200).json({ message: "Success! Welcome " + user.userName });
                }
                else {
                    res.status(401).json({ message: "Authentication failed! Incorrect password" });
                }
            });
        }
        else {
            res.status(401).json({ message: "Authentication failed! User not found" });
        }
    });
};
