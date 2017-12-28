"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var User_1 = require("../models/User");
var jwt = require("jsonwebtoken");
var db_config_1 = require("../config/db.config");
/**
 * POST /signup
 * Sign-up action
 */
exports.postSignup = function (req, res, next) {
    // make sure the email isn't already in use
    User_1.default.findOne({ email: req.body.email }, function (err, user) {
        if (err) {
            return res.status(500).json({ message: "Failed finding user in DB" });
        }
        if (user) {
            // email is already in use
            // TODO: give a flash message
            // return res.redirect("/signup");
            return res.status(409).json({ message: "Email is already in use" });
        }
        // make sure username isn't already in use
        User_1.default.findOne({ userName: req.body.userName }, function (err, user) {
            if (err) {
                console.error("Failed finding user in DB");
                return res.status(500).json({ message: "Failed finding user in DB" });
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
                userName: req.body.userName,
                password: req.body.password,
                email: req.body.email
            });
            User_1.default.schema.statics.createUser(newUser, function (err, user) {
                if (err) {
                    console.error("Failed creating user");
                    throw err;
                }
                else {
                    console.log(user);
                    // log user in and send them to the home page
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
    // is information correct
    User_1.default.findOne({ userName: req.body.userName }, function (err, user) {
        if (err) {
            console.error("Failed finding user in DB");
            return res.status(500).json({ message: "Failed finding user in DB" });
        }
        if (user) {
            // compare pw to DB pw
            user.comparePassword(req.body.password, function (err, isMatch) {
                if (err) {
                    console.error("Failed comparing PWs");
                    return res.status(500).json({ message: "Failed comparing PWs" });
                }
                if (isMatch) {
                    // Success! Log user in & give them a web token
                    // The payload contains all the data we want to be able to access locally that shouldn't change
                    var payload = {
                        "userName": user.userName,
                        "admin": user.admin
                    };
                    jwt.sign(payload, db_config_1.default.secret, { expiresIn: 60 * 15, issuer: "Boz", subject: "AuthenticationToken" }, function (err, token) {
                        if (err) {
                            console.error("Failed signing token");
                            return res.status(500).json({ message: "Failed signing token" });
                        }
                        else {
                            // Persist token (store to localStorage and/or cookie on the front end)
                            // All new requests should verify the web token
                            // When token is valid, respond, otherwise send an error
                            console.log("Token created!");
                            User_1.default.findOne(user, function (err, doc) {
                                if (err) {
                                    console.error("Failed finding user in DB");
                                    return res.status(500).json({ message: "Failed finding user in DB" });
                                }
                                else if (doc) {
                                    doc.accessToken = token;
                                    doc.save();
                                }
                                else {
                                    return res.status(500).json({ message: "The user was not found. Couldn't provide the intended user with a token" });
                                }
                            });
                            return res.status(200).json({ "token": token, message: "Success! Welcome " + user.userName });
                        }
                    });
                }
                else {
                    // Not a match
                    return res.status(500).json({ message: "Authentication failed! Incorrect password" });
                }
            });
        }
        else {
            return res.status(500).json({ message: "Authentication failed! User not found" });
        }
    });
};
