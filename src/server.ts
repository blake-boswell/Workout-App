import * as express from "express";
import * as mongoose from "mongoose";
import * as bodyParser from "body-parser";

import * as UserController from "./controllers/UserController";

const app = express();

// connect to mongo
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost/workoutApp", {
    useMongoClient: true
});

mongoose.connection.on("error", () => {
  console.log("MongoDB connection error. Please make sure MongoDB is running.");
  process.exit();
});

const port = 8080 || process.env.port;

// middleware for parsing application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// middleware for parsing application/json
app.use(bodyParser.json());

// app routes
app.get("/", function(req, res, next) {
    res.send("<h1>Welcome Home</h1>");
});
app.post("/api/signup", UserController.postSignup);
app.post("/api/login", UserController.postLogin);

// start express server
app.listen(port, function() {
    console.log("Connected to port " + port);
});