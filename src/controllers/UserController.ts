import { default as User } from "../models/User";
import { Request, Response, NextFunction } from "express";
import * as bcrypt from "bcrypt";

/**
 * POST /signup
 * Sign-up action
 */
export let postSignup = function(req: Request, res: Response, next: NextFunction) {

    // make sure the email isn't already in use
    User.findOne({email: req.body.email}, function(err, user) {
        if(err) {
            return next(err);
        }
        if(user) {
            // email is already in use
            // give a flash message
            return res.redirect("/signup");
        }
        // make sure username isn't already in use
        User.findOne({userName: req.body.userName}, function(err, user) {
            if(err) {
                return next(err);
            }
            if(user) {
                // username is already in use
                // give a flash message
                return res.redirect("/signup");
            }
        });
        // email is unique
        // hash pw with bcrypt
        bcrypt.genSalt(10, function(err, salt) {
            if(err) {
                console.error("Failed generating salt.");
                next(err);
            }
            bcrypt.hash(req.body.password, salt, function(err, hash) {
                if(err) {
                    console.error("Could not hash password");
                    next(err);
                }
                const newUser = new User({
                    userName: req.body.userName,
                    password: hash,
                    email: req.body.email
                });

                newUser.save(function(err) {
                    if(err) {
                        return next(err);
                    }
                }).then(function() {
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
export let postLogin = function(req: Request, res: Response, next: NextFunction) {
    // is information correct
    User.findOne({userName: req.body.userName}, function(err, user) {
        if(err) {
            return next(err);
        }
        console.log("user:");
        console.log(user);
        if(user) {
            // compare pw to DB pw
            bcrypt.compare(req.body.password, user.password, function(err, response) {
                if(err) {
                    return next(err);
                }
                if(response) {
                    // Success! Log user in & give them a web token
                    res.status(200).json({message: "Success! Welcome " + user.userName});
                } else {
                    res.status(401).json({message: "Authentication failed! Incorrect password"});
                }
            });
        } else {
            res.status(401).json({message: "Authentication failed! User not found"});
        }
    });
};