require("dotenv").config();
const express = require("express");
const passport = require("passport");

const connection = require("./connection");
const userRouter = require("./routes/user");
const { registerStrategy, loginStrategy, verifyStrategy } = require("./middleware/auth");

const app = express();

app.use(express.json());

passport.use("register", registerStrategy);
passport.use("login", loginStrategy);
passport.use(verifyStrategy);

app.use("/user", userRouter);
app.get("/", (req, res) => res.status(200).json({msg: "Hello World"}));

app.listen(process.env.HTTP_PORT, () => {
    console.log("Server Online");
    connection.authenticate();
    connection.sync({alter: true});
});
