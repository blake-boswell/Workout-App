/// <reference types="express" />
import { Request, Response, NextFunction } from "express";
import { ValidationChain } from "express-validator/check";
/**
 * POST /signup
 * Sign-up action
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
 */
export declare let postLogin: (req: Request, res: Response, next: NextFunction) => void;
