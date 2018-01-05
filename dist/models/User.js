"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var mongoose = require("mongoose");
var bcrypt = require("bcrypt");
var userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    admin: {
        type: Boolean,
        default: false
    },
    accessToken: {
        type: String
    },
    info: {
        height: String,
        weight: String,
        age: String,
        about: String,
        public: {
            type: Boolean,
            default: true
        }
    },
    _followers: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "User"
        }],
    _following: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "User"
        }],
    _userPosts: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "Post"
        }],
    _comments: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "Comment"
        }],
    _savedPosts: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "Post"
        }],
    _snaggedWorkouts: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "Workout"
        }],
    _snaggedExercises: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "Exercise"
        }],
    _exercisesCreated: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "Exercise"
        }],
    _workouts: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: "Workout"
        }],
    isDeleted: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});
userSchema.statics.createUser = function (newUser, callback) {
    bcrypt.genSalt(10, function (err, salt) {
        if (err) {
            console.error("Failed generating salt.");
            throw err;
        }
        bcrypt.hash(newUser.password, salt, function (err, hash) {
            if (err) {
                console.error("Could not hash password");
            }
            else {
                newUser.password = hash;
                newUser.save(callback);
            }
        });
    });
};
userSchema.methods.comparePassword = function (candidatePassword, callback) {
    // compare pw to DB pw
    bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
        callback(err, isMatch);
    });
};
var User = mongoose.model("User", userSchema);
exports.default = User;
