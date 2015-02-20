// module dependencies
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var flash = require('connect-flash');
var morgan = require('morgan');
var passport = require('passport');


var app = express();	//initialize express
require('./passport.js')(passport);	//pass passport for configuration

// view engine setup
app.set('views', path.join(__dirname, 'views'));	//serve all the views from the views folder
app.set('view engine', 'jade');		//our template engine is 'jade'

// middlewares and configurations 
app.use(morgan('dev'));		//log every request to the console
app.use(express.static(path.join(__dirname, 'public')));	//serve all the files that are in public folder
app.use(bodyParser.json());		
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({ 
	secret: 'catsoninternet',
	resave: false,
	saveUninitialized: true 
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// routes
require('./routes.js')(app, passport);	// load our routes and pass in our app and passport configurations

// launch our server
var server = app.listen(3000, function () {

  var host = server.address().address
  var port = server.address().port

  console.log('Server listening at http://%s:%s', host, port)

});