import * as express from "express";
import * as mongoose from "mongoose";
import * as bodyParser from "body-parser";
import * as session from "express-session";
import * as mongo from "connect-mongo";
import * as dotenv from "dotenv";
import * as mongodb from "mongodb";
import * as passport from "passport";
import * as flash from "express-flash";
import * as expressValidator from "express-validator";



// Controllers for route handling
import * as UserController from "./controllers/UserController";

dotenv.config();
const MongoStore = mongo(session);

import * as passportConfig from "./config/passport";
console.log(passportConfig);

// Starting express app
const app = express();

// Connect to mongoDB using mongoose
mongoose.connect(process.env.MONGODB_URI || <string>process.env.DB_URL, {
    useMongoClient: true
});

// If connection cannot be made to mongoDB
mongoose.connection.on("error", () => {
  console.log("MongoDB connection error. Please make sure MongoDB is running.");
  process.exit();
});

const port = process.env.port || 8080;

// Session options
const sessionOptions = {
    resave: true,
    saveUninitialized: true,
    secret: <string>process.env.SESSION_SECRET,
    store: new MongoStore({ mongooseConnection: mongoose.connection, autoReconnect: true }),
    cookie: {
        secure: false, // use secure cookies in production, but you must use HTTPS for it
        maxAge: 30*24*60*60*1000 // 30 days
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

app.use(function(req, res, next) {
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
app.get("/", function(req, res, next) {
    res.json({ message: "Welcome to the Home Page!", flashMessage: res.locals.sessionFlash });
});
app.post("/api/signup", UserController.signupValidation ,UserController.postSignup);
app.get("/signup", function(req, res) {
    res.json({ message: "Welcome to the sign-up page!", flashMessage: res.locals.sessionFlash });
});
app.post("/api/login", UserController.postLogin);
app.get("/login", function(req, res) {
    res.json({ message: "Welcome to the Login Page!", flashMessage: res.locals.sessionFlash });
});

// start express server
app.listen(port, function() {
    console.log("Connected to port " + port);
});