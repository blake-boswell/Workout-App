import * as passport from "passport";
import * as passportLocal from "passport-local";
import * as passportJWT from "passport-jwt";
import { default as User, UserType } from "../models/User";
import { Request, Response, NextFunction } from "express";

const LocalStrategy = passportLocal.Strategy;
const JWTStrategy = passportJWT.Strategy;
const options = {
    secretOrKey: process.env.TOKEN_SECRET,
    jwtFromRequest: passportJWT.ExtractJwt.fromAuthHeaderAsBearerToken(),
};

// Session configuration
// ID is stored to req.user and is used to find the user
passport.serializeUser(function(user: any, done: any) {
    done(undefined, user._id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user: any) {
        done(err, user);
    });
});

// // Local Strategy configuration
// // Sends an error (undefined if there is none), a user (false if there is none) through the done callback
passport.use(new LocalStrategy({ usernameField: "email" },
    function(email: string, password: string, done: any) {
        User.findOne({ email: email }, function(err: Error, user: UserType) {
            if(err) {
                return done(err);
            }
            if(!user) {
            return done(undefined, false, { message: "Incorrect email." });
            }
            user.comparePassword(password, function(err: any, isMatch: boolean) {
                if(err) {
                    return done(err);
                }
                if(!isMatch) {
                    return done(undefined, false, { message: "Incorrect password." });
                }
                return done(undefined, user);
            });
        });
}));

// JWT Strategy configuration
passport.use(new JWTStrategy(options, function(jwt_payload, done) {
    User.findOne({ _id: jwt_payload._id }, function(err: Error, user: any) {
       if(err) {
           return done(err);
       }
       if(!user) {
           return done(undefined, false, { message: "Could not find user." });
       }
       return done(undefined, user);
    });
}));