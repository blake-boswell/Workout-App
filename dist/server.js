"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var express = require("express");
var mongoose = require("mongoose");
var bodyParser = require("body-parser");
var UserController = require("./controllers/UserController");
var db_config_1 = require("./config/db.config");
var app = express();
// connect to mongo
mongoose.connect(process.env.MONGODB_URI || db_config_1.default.url, {
    useMongoClient: true
});
mongoose.connection.on("error", function () {
    console.log("MongoDB connection error. Please make sure MongoDB is running.");
    process.exit();
});
var port = 8080 || process.env.port;
// middleware for parsing application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));
// middleware for parsing application/json
app.use(bodyParser.json());
// app routes
app.get("/", function (req, res, next) {
    res.send("<h1>Welcome Home</h1>");
});
app.post("/api/signup", UserController.postSignup);
app.post("/api/login", UserController.postLogin);
// start express server
app.listen(port, function () {
    console.log("Connected to port " + port);
});
