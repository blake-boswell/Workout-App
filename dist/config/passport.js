"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var passport = require("passport");
var passportLocal = require("passport-local");
var passportJWT = require("passport-jwt");
var User_1 = require("../models/User");
var LocalStrategy = passportLocal.Strategy;
var JWTStrategy = passportJWT.Strategy;
var options = {
    secretOrKey: process.env.TOKEN_SECRET,
    jwtFromRequest: passportJWT.ExtractJwt.fromAuthHeaderAsBearerToken(),
};
// Session configuration
// ID is stored to req.user and is used to find the user
passport.serializeUser(function (user, done) {
    done(undefined, user._id);
});
passport.deserializeUser(function (id, done) {
    User_1.default.findById(id, function (err, user) {
        done(err, user);
    });
});
// // Local Strategy configuration
// // Sends an error (undefined if there is none), a user (false if there is none) through the done callback
passport.use(new LocalStrategy(function (username, password, done) {
    User_1.default.findOne({ username: username }, function (err, user) {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(undefined, false, { message: "Incorrect username." });
        }
        user.comparePassword(password, function (err, isMatch) {
            if (err) {
                return done(err);
            }
            if (!isMatch) {
                return done(undefined, false, { message: "Incorrect password." });
            }
            return done(undefined, user);
        });
    });
}));
// JWT Strategy configuration
passport.use(new JWTStrategy(options, function (jwt_payload, done) {
    User_1.default.findOne({ _id: jwt_payload._id }, function (err, user) {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(undefined, false, { message: "Could not find user." });
        }
        return done(undefined, user);
    });
}));
