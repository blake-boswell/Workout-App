import * as mongoose from 'mongoose';
import * as bcrypt from 'bcrypt';

export interface IUser extends mongoose.Document {
    username: string;
    displayName: string;
    password: string;
    email: string;
    admin: boolean;
    accessToken?: string;
    verificationToken?: string;
    resetToken?: string;
    isDeleted: boolean;
    createdAt: Date;
    isActive: boolean;

    createUser: (newUser: IUser, callback: any) => void;
    comparePassword: (candidatePassword: string, callback: any) => void;
  }
export type UserType = IUser & mongoose.Document;

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    displayName: {
        type: String,
        required: true
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
    verificationToken: {
        type: String
    },
    resetToken: {
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
        ref: 'User'
    }],
    _following: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    _userPosts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Post'
    }],
    _comments: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Comment'
    }],
    _savedPosts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Post'
    }],
    _snaggedWorkouts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Workout'
    }],
    _snaggedExercises: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Exercise'
    }],
    _exercisesCreated: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Exercise'
    }],
    _workouts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Workout'
    }],
    isDeleted: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    isActive: {
        type: Boolean,
        default: false
    }
});

// Password hashing middleware
// inspired by https://www.mongodb.com/blog/post/password-authentication-with-mongoose-part-1
// MUST USE .save TO HASH THE PW
userSchema.pre('save', function(next) {
    const user = this;
    // Hash pw if it is new/modified
    if(!user.isModified('password'))
        return next();

    // Gen salt and hash pw
    bcrypt.genSalt(10, (err, salt) => {
        if(err)
            return next(err);
        bcrypt.hash(user.password, salt, (err, hash) => {
            if(err)
                return next(err);
            // Override the pw with the hash
            user.password = hash;
            next();
        });
    });
});

userSchema.methods.comparePassword = function(candidatePassword: String, callback) {
    // compare pw to DB pw
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if(err)
            return callback(err);
        callback(undefined, isMatch);
    });
};

userSchema.methods.updatePassword = (newPassword: String, callback) => {
    // console.log('This ', this);
    hashPassword(newPassword, (err, hash) => {
        if(err)
            callback(err);
        else {
            // Keep working in here...
            console.log('This ', this, '\nModel ', this.model);
            this.default.model.password = hash;
            // this.save();
            callback(undefined);
        }
    });
};

const hashPassword = (password: String, callback)  => {
    bcrypt.genSalt(10, (err, salt) => {
        if(err)
            callback(err, undefined);
        else {
            bcrypt.hash(password, salt, (err, hash) => {
                if(err)
                    callback(err, undefined);
                else
                    callback(undefined, hash);
            });
        }
    });
};


const User = mongoose.model<UserType>('User', userSchema);
export default User;