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
 * Send verification email
 */
export declare let sendVerificationEmail: (receivers: String, link: String, callback: any) => void;
export declare let verify: (req: Request, res: Response) => void;
