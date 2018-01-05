/// <reference types="mongoose" />
import * as mongoose from "mongoose";
export interface IUser extends mongoose.Document {
    username: string;
    password: string;
    email: string;
    admin: boolean;
    accessToken?: string;
    isDeleted: boolean;
    createdAt: Date;
    createUser: (newUser: IUser, callback: any) => void;
    comparePassword: (candidatePassword: string, callback: any) => void;
}
export declare type UserType = IUser & mongoose.Document;
declare const User: mongoose.Model<UserType>;
export default User;
