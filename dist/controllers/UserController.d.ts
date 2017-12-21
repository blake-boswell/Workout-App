/// <reference types="express" />
import { Request, Response, NextFunction } from "express";
/**
 * POST /signup
 * Sign-up action
 */
export declare let postSignup: (req: Request, res: Response, next: NextFunction) => void;
/**
 * POST /login
 * Login action
 */
export declare let postLogin: (req: Request, res: Response, next: NextFunction) => void;
