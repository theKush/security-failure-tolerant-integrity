// passport.js
// here we will create strategies for passport to handle user login and authentication
var LocalStrategy = require('passport-local').Strategy;
var _ = require('lodash');

// user information, simple solution to not use mongodb
var users = [
    { id: 1, username: 'bob', password: 'password', email: 'bob@example.com' }
];

// expose this function to our app using module.exports
module.exports = function (passport) {
	// =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function (user, done) {
    	done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function (id, done) {
    	var user = _.find(users, function(chr) { return chr.id == id; });
    	console.log('user', user);
    	done(null, user);
    });

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================

  	passport.use('local', new LocalStrategy({
  		usernameField: 'username',	//set what should an user use during login
  		passwordField: 'password',
  		passReqToCallback: true	// allows us to pass back the entire request to the callback
  	},
  	function (req, username, password, done) {	// callback with username and password from our form

  		// find a user whose username is the same as the form input
  		// we are checking to see if the user tryping to login already exists
  		var user = _.find(users, function(chr) { return chr.username == username; });

  		if (!user) {
  			return done(null, false, req.flash('loginMessage', 'No user found'));
  		}

  		if (user.password !== password) {
  			return done(null, false, req.flash('loginMessage', 'Oop! Wrong password'));
  		}

  		return done(null, user);
  	}));
};