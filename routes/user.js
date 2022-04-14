const router = require("express").Router();
const jwt = require("jsonwebtoken");
const passport = require("passport");

const register = (req, res) => req.user.name ? res.status(201).json({msg: `Registered: ${req.user.name}`}) : res.status(401).json({msg: "User already exists"});

const login = async(req, res, next) => {
    passport.authenticate("login", async(err, user, info) => {
	console.log(err);
	console.log(user);
	console.log(info);

        try {
            if (err) {
                res.status(500).json({msg: "Internal Server Error"});
            } else if (!user) {
                res.status(403).json({msg: "Unauthorized"});
            } else {
                const fn = async(error) => error ? next(error) : res.status(200).json({user, token: jwt.sign({user: {id: user.id, name: user.name}}, process.env.SECRET_KEY)});
                req.login(user, {session: false}, fn);
            }
        } catch(error) {
            return next(error);
        }
    })(req, res, next);
};

const profile = (req, res) => {
    res.status(200).json({msg: "profile", user: req.user, token: req.query.secret_token});
};

router.post("/register", passport.authenticate("register", {session: false}), register);
router.post("/login", login);
router.get("/profile", passport.authenticate("jwt", {session: false}), profile);

module.exports = router;
