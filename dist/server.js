"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var express = require("express");
var app = express();
var port = 8080 || process.env.port;
app.get("/", function (req, res, next) {
    res.send("<h1>Welcome Home</h1>");
});
app.listen(port, function () {
    console.log("Connected to port " + port);
});
