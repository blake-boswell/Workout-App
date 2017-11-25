import * as express from "express";

const app = express();
const port = 8080 || process.env.port;

app.get("/", function(req, res, next) {
    res.send("<h1>Welcome Home</h1>");
});

app.listen(port, function() {
    console.log("Connected to port " + port);
});