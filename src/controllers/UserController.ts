import User from "../models/User";
import { Request, Response, NextFunction } from "express";
import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import config from "../config/db.config";

/**
 * POST /signup
 * Sign-up action
 */
export let postSignup = function(req: Request, res: Response, next: NextFunction) {

    // make sure the email isn't already in use
    User.findOne({email: req.body.email}, function(err: any, user: any) {
        if(err) {
            return res.status(500).json({message: "Failed finding user in DB"});
        }
        if(user) {
            // email is already in use
            // TODO: give a flash message
            // return res.redirect("/signup");
            return res.status(409).json({message: "Email is already in use"});
        }
        // make sure username isn't already in use
        User.findOne({userName: req.body.userName}, function(err: any, user: any) {
            if(err) {
                console.error("Failed finding user in DB");
                return res.status(500).json({message: "Failed finding user in DB"});
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
                userName: req.body.userName,
                password: req.body.password,
                email: req.body.email
            });
            User.schema.statics.createUser(newUser, function(err: any, user: any) {
                if(err) {
                    console.error("Failed creating user");
                    throw err;
                } else {
                    console.log(user);
                    // log user in and send them to the home page
                    // res.redirect("../login");
                    res.status(200).json({message: "Success! Welcome " + newUser});
                }
            });
        });
    });
};

/**
 * POST /login
 * Login action
 */
export let postLogin = function(req: Request, res: Response, next: NextFunction) {
    // is information correct
    User.findOne({userName: req.body.userName}, function(err, user) {
        if(err) {
            console.error("Failed finding user in DB");
            return res.status(500).json({message: "Failed finding user in DB"});
        }
        if(user) {
            // compare pw to DB pw
            user.comparePassword(req.body.password, function(err: any, isMatch: boolean) {
                if(err) {
                    console.error("Failed comparing PWs");
                    return res.status(500).json({message: "Failed comparing PWs"});
                }
                if(isMatch) {
                    // Success! Log user in & give them a web token
                    // The payload contains all the data we want to be able to access locally that shouldn't change

                    const payload = {
                        "userName": user.userName,
                        "admin": user.admin
                    };
                    jwt.sign(payload, config.secret, {expiresIn: 60*15, issuer: "Boz", subject: "AuthenticationToken"}, function(err, token) {
                        if(err) {
                            console.error("Failed signing token");
                            return res.status(500).json({message: "Failed signing token"});
                        } else {
                            // Persist token (store to localStorage and/or cookie on the front end)
                            // All new requests should verify the web token
                            // When token is valid, respond, otherwise send an error
                            console.log("Token created!");
                            User.findOne(user, function(err, doc) {
                                if(err) {
                                    console.error("Failed finding user in DB");
                                    return res.status(500).json({message: "Failed finding user in DB"});
                                } else if(doc) {
                                    doc.accessToken = token;
                                    doc.save();
                                } else {
                                    return res.status(500).json({message: "The user was not found. Couldn't provide the intended user with a token"});
                                }
                            });
                            return res.status(200).json({"token": token, message: "Success! Welcome " + user.userName});
                        }
                     });


                } else {
                    // Not a match
                    return res.status(500).json({message: "Authentication failed! Incorrect password"});
                }
            });
        } else {
            return res.status(500).json({message: "Authentication failed! User not found"});
        }
    });
};