import User, { UserType } from '../models/User';
import { Request, Response, NextFunction } from 'express';
import * as passport from 'passport';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { check, validationResult, ValidationChain } from 'express-validator/check';
import { matchedData, sanitize } from 'express-validator/filter';
import * as nodemailer from 'nodemailer';
import * as Mailgun from 'mailgun-js';
import * as crypto from 'crypto';
import { Promise } from 'mongoose';

/**
 * POST /signup
 * Sign-up action
 *
 * email
 * username
 * displayName
 * password
 */
export let postSignup = (req: Request, res: Response) => {

    Promise.all([
        checkIfSignupCredentialsAreUnique(req.body),
        registerNewUser(req.body)
    ]).then( function(values) {
        const user = values[1];
        const token = user.verificationToken;
        const link = 'http://' + req.get('host') + '/verify/' + token;
        sendVerificationEmail(req.body.email, link);
        return user;
    }).then((user) => {
        req.session.sessionFlash = {
            type: 'Success',
            message: 'Success! Check your email for a verification link ' + user.username
        };
        res.status(200).redirect('/login');
    }).catch((err) => {
        req.session.sessionFlash = {
            type: 'Error',
            message: err.message
        };
        res.status(err.code).redirect('/signup');
    });
};

const registerNewUser = (body: any) => {
    return new Promise((resolve, reject) => {
        generateRandomString().then((token) => {
            const newUser = new User({
                username: body.username,
                displayName: body.displayName,
                password: body.password,
                email: body.email,
                verificationToken: token
            });
            newUser.save().then((user) => {
                resolve(user);
            });
        }).catch((err) => {
            reject(err);
        });
    });
};

const checkIfSignupCredentialsAreUnique = (body: any) => {
    return Promise.all([checkIfEmailIsUnique(body.email), checkIfUsernameIsUnique(body.username)]);
};

const checkIfEmailIsUnique = (email: String) => {
    return new Promise((resolve: any, reject: any) => {
        User.findOne({email: email}, (err: Error, user: UserType) => {
            if(err) {
                reject(err);
            } else if(user) {
                // email is already in use
                reject(new Error('That email is already in use'));
            } else {
                resolve(true);
            }
        });
    });
};

const checkIfUsernameIsUnique = (username: String) => {
    return new Promise((resolve: any, reject: any) => {
        User.findOne({username: username}, (err: Error, user: UserType) => {
            if(err) {
                reject(err);
            } else if(user) {
                // username is already in use
                reject(new Error('That username is already in use'));
            } else {
                resolve(true);
            }
        });
    });
};


/**
 * Generates a random string to be appended as a token to routes
 * EX: 5c355a1730cbf8487757a7f6451d020659f8f4c1
 */
const generateRandomString = () => {
    return new Promise((resolve: any, reject: any) => {
        crypto.randomBytes(20, (err, buf) => {
            if(err) {
                reject(err);
            } else if(buf) {
                const token = buf.toString('hex');
                resolve(token);
            }
        });
    });
};

/**
 * GET /user/:username
 * route param: username
 *
 * @param req Request object
 * @param res Response object
 */
export let getUserByUsername = (req: Request, res: Response) => {
    const username = req.params.username;
    User.findOne({username: username}).then(function(user: UserType) {
        res.send(user);
    }).catch(function(err: any) {
        const errorMsg = new Error('User not found! ' + err);
        return errorHandler(req, res, 404, errorMsg);
    });
};

/**
 * POST /signup
 * Validation Middleware
 */
export let signupValidation: ValidationChain [] = [
    check('email').exists().withMessage('You must enter an email address.')
        .isEmail().withMessage('You must enter a valid email address.')
        .normalizeEmail(),
    check('password').exists().withMessage('You must enter a password.')
        .isLength({ min: 6 }).withMessage('Your password must be at least 6 characters long')
        .matches(/^(?=.*\d)(?=.*[A-Z])(?=.*[a-z]).+$/).withMessage('Your password must contain a number, a capital letter, and a lowercase letter.'),
    check('confirmPassword').exists().withMessage('Please confirm your password')
        .custom((value, { req }) => value === req.body.password).withMessage('Your passwords do not match.'),
    check('displayName').exists().withMessage('You must enter a display name.')
        .matches(/^[a-zA-Z0-9_-]*$/).withMessage('You may only use letters, numbers, and the symbols - and _.'),
    check('username').exists().withMessage('You must enter a username.')
        .isAlphanumeric().withMessage('You may only use letters and numbers.')
];

/**
 * POST /login
 * Login action
 *
 * email
 * password
 * @param req Request object
 * @param res Response object
 * @param next Next object
 */
export let postLogin = (req: Request, res: Response) => {
    User.findOne({
        email: req.body.email
    }).then((user: UserType) => {
        if(!user.isActive) {
            const errorMsg = new Error('You must activate your account with the link sent to your email first.');
            return errorHandler(req, res, 500, errorMsg, 'login');
        }
        passportAuthenticateAsync('local', req, res).then((user: UserType, info: any) => {
            if(info) {
                console.log('[Local Authenticate]You got some info: ', info);
            }
            passportLoginAsync(user, req).then(() => {
                req.session.sessionFlash = {
                    type: 'Success',
                    message: 'Successfully logged in!'
                };
                return res.status(200).redirect('/');
            });
        });
    }).catch((err: Error) => {
        console.log('The Error: ', err);
        errorHandler(req, res, 404, err, '/login');
    });
};

/**
 * Promisified version of req.login from passport
 *
 * @param user User to be logged in
 * @param req Request object
 */
const passportLoginAsync = (user: UserType, req: Request) => {
    return new Promise((resolve, reject) => {
        req.login(user, (err: Error) => {
            if(err) {
                reject(err);
            } else {
                resolve();
            }
        });
    });
};

/**
 * Promisified version of passport.authenticate from passport
 *
 * @param strategy Passport strategy
 * @param req Request object
 * @param res Response object
 */
const passportAuthenticateAsync = (strategy: any, req: Request, res: Response) => {
    return new Promise((resolve, reject) => {
        passport.authenticate(strategy, (err: Error, user: UserType, info: any) => {
            if(err) {
                reject(err);
            } else if(!user) {
                reject();
            } else {
                resolve(user, info);
            }
        })(req, res);
    });
};

/**
 * POST /logout
 * Logout action
 * @param req Request object
 * @param res Response object
 */
export let postLogout = (req: Request, res: Response) => {
    // Log user out of session
    req.logout();
    res.redirect('/');
};

/**
 * GET /forgot/
 * @param req Request Object
 * @param res Response Object
 */
export let getForgotPassword = (req: Request, res: Response) => {
    res.send({message: 'Forgot Password Page!'});
};

/**
 * POST /forgot
 *
 * email
 * Forgot password action
 * @param req Request object
 * @param res Response object
 */
// export let postForgotPassword = (req: Request, res: Response) => {
//     // Generate JWT
//     const userEmail = req.body.email;
//     User.findOne({ email: userEmail }, (err, user) => {
//         // Append JWT to email
//         generateRandomString((err, token) => {
//             if(err)
//                 return errorHandler(req, res, 500, err, 'forgot');
//             if(user) {
//                 const link = 'http://' + req.get('host') + '/update/password/' + token;
//                 // Set the token on the user for verification
//                 user.resetToken = token;
//                 user.save((err) => {
//                     if(err)
//                         return errorHandler(req, res, 500, err, 'forgot');
//                     // Send email
//                     forgotPasswordEmail(userEmail, link, (err) => {
//                         if(err)
//                             return errorHandler(req, res, 500, err, 'forgot');
//                         return res.send({ message: 'Email sent!' });
//                     });
//                 });
//             } else {
//                 const err = new Error('Could not find a user with that email address');
//                 return errorHandler(req, res, 404, err, 'forgot');
//             }
//         });
//     });
// };

export let postForgotPassword = (req: Request, res: Response) => {
    User.findOne({
        email: req.body.email
    }).then((user) => {
        generateRandomString().then((token) => {
            const link = 'http://' + req.get('host') + '/update/password/' + token;
            // Set the token on the user for verification
            user.resetToken = token;
            user.save().then(() => {
                sendForgotPasswordEmail(user.email, link).then(() => {
                    res.send({message: 'A password reset link has been sent to your email.'});
                });
            });
        });
    }).catch((err) => {
        req.session.sessionFlash = {
            type: 'Error',
            message: err.message
        };
        res.status(err.code).redirect('/signup');
    });
};

/**
 * POST action /update/password/:token
 * @param req Request Object
 * @param res Response Object
 */
export let postChangePassword = (req: Request, res: Response) => {
    // Grab token
    const token = req.params.token;
    // Find user by token
    User.findOne({ resetToken: token }, (err: any, user: UserType) => {
        if(err)
            return errorHandler(req, res, 404, err, '404');
        if(user) {
            // Update Password
            console.log('Updating PW..');
            user.password = req.body.newPassword;
            // Remove token
            user.resetToken = undefined;
            user.save(function(err) {
                if(err)
                    return errorHandler(req, res, 500, err);
                return res.send({message: 'Password successfully updated!'});
            });
        } else {
            // Redirect to 404 page
            return res.send({ message: '404 Page Not Found.' });
        }
    });
};

export let generatePasswordUpdatePage = (req: Request, res: Response) => {
    // Generate the Password Update Form
    // res.sendFile('updatePassword');
    res.send({message: 'Update PW Page'});
};

/**
 * Send email
 * @param to who the email is sent to
 * @param subject the subject of the email
 * @param message the contents of the email
 * @param callback callback with the parameters error and data
 */
export let sendEmail = (to: String, subject: String, message: string, callback: any) => {
    const api_key = process.env.MAIL_API_KEY;
    const DOMAIN = process.env.MAIL_TEST_DOMAIN;
    const mailgun = new Mailgun({apiKey: api_key, domain: DOMAIN});

    console.log(mailgun);
    const data = {
      from: 'Bozzy <blake.w.boswell@gmail.com>',
      to: to,
      subject: subject,
      text: message
    };

    mailgun.messages().send(data, (err, body) => {
        if(err) {
            console.log('FAILURE!\n' + err);
            callback(err, undefined);
        } else {
            console.log('SUCCESS!\n' + body);
            callback(undefined, body);
        }
    });
};

/**
 * Send verification email
 * @param receiver who the email is sent to
 * @param link email link to verify account
 */
export let sendVerificationEmail = (receiver: String, link: String) => {
    return new Promise((resolve: any, reject: any) => {
        const to = receiver;
        const subject = 'Verify Email';
        const message = 'Please click the following link to verify and activate your account\n' + link;

        sendEmail(to, subject, message, (err: Error, result: any) => {
            if(err) {
                reject(err);
            } else {
                resolve(result);
            }
        });
    });
};

/**
 * Send forgot password email link
 * @param receiver who the email is sent to
 * @param link email link to verify account
 * @param callback callback with the parameters error and data
 */
export let sendForgotPasswordEmail = (receiver: String, link: String) => {
    return new Promise((resolve: any, reject: any) => {
        const to = receiver;
        const subject = 'Forgot Password';
        const message = 'Please click on the following link to change your password\n' + link;

        sendEmail(to, subject, message, (err: Error, result: any) => {
            if(err) {
                reject(err);
            } else {
                resolve(result);
            }
        });
    });
};

/**
 * Verify and activate user account
 * @param req Request object
 * @param res Response object
 */
export let verify = (req: Request, res: Response) => {
    User.findOne({verificationToken: req.params.id}, (err, user) => {
        if(err) {
            return res.send(err);
        }
        if(!user) {
            const err = new Error('User not found.');
            return errorHandler(req, res, 404, err, );
        }
        if(!user.isActive) {
            user.isActive = true;
            user.verificationToken = undefined;
            console.log(user);
            user.save((err) => {
                if(err) {
                    return errorHandler(req, res, 401, err, 'login');
                }
                console.log(user.username + ' has been activated.');
                const html = '<h1>SUCCESS!</h1><br /><h3>' + user.username + ', you are now an active user!</h3>';
                return res.send(html);
            });
        } else {
            const html = '<h1>This user is already activated</h1>';
            console.log(user.username + ' attempted to activate his/her account, but it has already been activated.');
            return res.send(html);
        }
    });
};

/**
 * Creates an error flash message and optionally redirects the user
 * @param req Request object
 * @param res Response object
 * @param statusCode HTTP status code
 * @param err Error object to be used as the message
 * @param redirectPage Page to redirect to (optional)
 */
const errorHandler = (req: Request, res: Response, statusCode: number, err: Error, redirectPage?: String) => {
    req.session.sessionFlash = {
        type: 'Error',
        message: err
    };
    if(redirectPage) {
        res.status(statusCode).redirect('/' + redirectPage);
    }
    console.log('Error in errorHandler\nError: ', err);
};