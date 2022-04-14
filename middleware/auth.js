const bcrypt = require("bcrypt");
const ExtractJWT = require("passport-jwt").ExtractJwt;
const JWTStrategy = require("passport-jwt").Strategy;
const LocalStrategy = require("passport-local").Strategy;

const User = require("../models/user");

const register = async (name, password, next) => {
    const saltRounds = parseInt(process.env.SALT_ROUNDS);
    
    try {
	if (!name) {
	    throw new Error("A name was not provided");
	}

	const salt = await bcrypt.genSalt(saltRounds);
	const hash = await bcrypt.hash(password, salt);
	const user = await User.build({name, password: hash});

	try {
	    await user.save();
	    next(null, user);
	} catch(error) {
	    next(null, {});
	}
    } catch(error) {
	next(error);
    }
};

const login = async (name, password, next) => {
    try {
	console.log("Testing 1");
	const user = await User.findOne({where: {name}});
		console.log(user);
	if (!user) {
	    return next(null, false, {msg: "Incorrect Username"});
	}

	const match = await bcrypt.compare(password, user.password);
	return match ? next(null, user) : next(null, false, {msg: "Incorrect password"});
    } catch(error) {
	console.log("Testing 2");
	return next(error);
    }
};

const verify = (token, next) => {
	try{
		next(null, token.user);
	} catch(error){
		next(error);
	}
};

const registerStrategy = new LocalStrategy({usernameField: "name", passwordField: "password"}, register);
const loginStrategy = new LocalStrategy({usernameField: "name", passwordField: "password"}, login);
const verifyStrategy = new JWTStrategy({secretOrKey: process.env.SECRET_KEY, jwtFromRequest: ExtractJWT.fromUrlQueryParameter("secret_token")}, verify);

module.exports = { registerStrategy, loginStrategy, verifyStrategy };
