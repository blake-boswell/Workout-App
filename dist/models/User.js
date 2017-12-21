"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var mongoose = require("mongoose");
var userSchema = new mongoose.Schema({
    userName: {
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
var User = mongoose.model("User", userSchema);
exports.default = User;