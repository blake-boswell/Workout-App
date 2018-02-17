/// <reference types="express" />
import { Request, Response, NextFunction } from "express";
import { ValidationChain } from "express-validator/check";
/**
 * POST /signup
 * Sign-up action
 *
 * email
 * username
 * displayName
 * password
 */
export declare let postSignup: (req: Request, res: Response, next: NextFunction) => void;
/**
 * POST /signup
 * Validation Middleware
 */
export declare let signupValidation: ValidationChain[];
/**
 * POST /login
 * Login action
 *
 * email
 * password
 */
export declare let postLogin: (req: Request, res: Response, next: NextFunction) => void;
/**
 * POST /logout
 * Logout action
 */
export declare let postLogout: (req: Request, res: Response) => void;
/**
 * GET /forgot/
 * @param req Request Object
 * @param res Response Object
 */
export declare let getForgotPassword: (req: Request, res: Response) => void;
/**
 * POST /forgot
 * Forgot password action
 */
export declare let postForgotPassword: (req: Request, res: Response) => void;
/**
 * POST action /update/password/:token
 * @param req Request Object
 * @param res Response Object
 */
export declare let postChangePasswordAction: (req: Request, res: Response) => void;
export declare let getChangePassword: (req: Request, res: Response) => void;
export declare let generatePasswordUpdatePage: (req: Request, res: Response) => void;
/**
 * Send email
 * @param to who the email is sent to
 * @param subject the subject of the email
 * @param message the contents of the email
 * @param callback callback with the parameters error and data
 */
export declare let sendEmail: (to: String, subject: String, message: string, callback: any) => void;
/**
 * Send verification email
 * @param receiver who the email is sent to
 * @param link email link to verify account
 * @param callback callback with the parameters error and data
 */
export declare let sendVerificationEmail: (receiver: String, link: String, callback: any) => void;
/**
 * Send forgot password email link
 * @param receiver who the email is sent to
 * @param link email link to verify account
 * @param callback callback with the parameters error and data
 */
export declare let forgotPasswordEmail: (receiver: String, link: String, callback: any) => void;
export declare let verify: (req: Request, res: Response) => void;
