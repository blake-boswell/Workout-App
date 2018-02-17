"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var express = require("express");
var mongoose = require("mongoose");
var bodyParser = require("body-parser");
var session = require("express-session");
var mongo = require("connect-mongo");
var dotenv = require("dotenv");
var passport = require("passport");
var flash = require("express-flash");
var expressValidator = require("express-validator");
// Controllers for route handling
var UserController = require("./controllers/UserController");
dotenv.config();
var MongoStore = mongo(session);
var passportConfig = require("./config/passport");
console.log(passportConfig);
// Starting express app
var app = express();
// Connect to mongoDB using mongoose
mongoose.connect(process.env.MONGODB_URI || process.env.DB_URL, {
    useMongoClient: true
});
// If connection cannot be made to mongoDB
mongoose.connection.on("error", function () {
    console.log("MongoDB connection error. Please make sure MongoDB is running.");
    process.exit();
});
var port = process.env.port || 8080;
// Session options
var sessionOptions = {
    resave: true,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET,
    store: new MongoStore({ mongooseConnection: mongoose.connection, autoReconnect: true }),
    cookie: {
        secure: false,
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    }
};
if (app.get("env") === "production") {
    app.set("trust proxy", 1); // trust first proxy
    sessionOptions.cookie.secure = true; // serve secure cookies
}
// express configuration
// app.set("port", port);
// to serve static files from the public folder (EX: CSS, images,...)
app.use(express.static("public"));
// setting up connect-mongo storage & session middleware
app.use(session(sessionOptions));
// setting up flash
app.use(flash());
app.use(function (req, res, next) {
    // if there's a flash message in the session request, make it available in the response, then delete it
    res.locals.sessionFlash = req.session.sessionFlash;
    delete req.session.sessionFlash;
    next();
});
// middleware for parsing application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));
// middleware for parsing application/json
app.use(bodyParser.json());
// middleware for validation
app.use(expressValidator());
app.use(passport.initialize());
app.use(passport.session());
// app routes
app.get("/", function (req, res, next) {
    console.log("Passport User: ", req.user);
    console.log("Passport is Auth: ", req.isAuthenticated());
    res.json({ message: "Welcome to the Home Page!", flashMessage: res.locals.sessionFlash });
});
app.post("/api/signup", UserController.signupValidation, UserController.postSignup);
app.get("/signup", function (req, res) {
    res.json({ message: "Welcome to the sign-up page!", flashMessage: res.locals.sessionFlash });
});
app.get("/verify/:id", UserController.verify);
app.post("/api/login", UserController.postLogin);
app.get("/login", function (req, res) {
    res.json({ message: "Welcome to the Login Page!", flashMessage: res.locals.sessionFlash });
});
app.post("/api/logout", UserController.postLogout);
app.get("/forgot", UserController.getForgotPassword);
app.post("/api/forgot", UserController.postForgotPassword);
app.get("/update/password/:token", UserController.generatePasswordUpdatePage);
app.post("/update/password/:token", UserController.postChangePasswordAction);
// start express server
app.listen(port, function () {
    console.log("Connected to port " + port);
});
