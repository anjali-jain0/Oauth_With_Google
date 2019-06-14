var express=require('express');
var app=express();
const passport =require('passport');
const GoogleStrategy = require('passport-google-oauth20');
const config = require('./config');
const cookieSession = require('cookie-session');

const mongoose=require('mongoose');

mongoose.connect('mongodb://localhost/oauth');

const db = mongoose.connection;

var UserSchema = new mongoose.Schema({
	username : String,
	googleid : String
});

const User = mongoose.model('User',UserSchema,'User');

app.use(cookieSession({
	maxAge : 24 * 60 * 60 * 1000,
	keys : [config.cookieKey]
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user,done) => {
	done( null,user._id);
});

passport.deserializeUser((id,done) => {
	const query = {_id:id};
	User.find(query,function(err,usr){
		if(err || usr.length ==0) throw err;
		if(usr.length>0){
			done( null,usr[0]);
		}
	});
});


passport.use(
	new GoogleStrategy({
		callbackURL : '/auth/google/redirect' ,
		clientID : config.clientID , 
		clientSecret : config.clientSecret
	} , (accessToken , refreshToken , profile , done) => {
		const query = {googleid : profile.id};
		User.find(query,function(err,user){
			if(err) throw err;
			if(user.length>0){
				console.log('Already have the user');
				done(null,user[0]);
			} else {
				const usr = User({username:profile.displayName,googleid:profile.id}).save(function(err){
					if(err) throw err;
					User.find({username:profile.displayName,googleid:profile.id},function(err,usr){
						if(err || usr.length ==0 ) throw err;
						if(usr.length>0){ 
							done(null,usr[0]);
						}
					});
			});
		}
		});
	})
);

const authCheck = (req , res , next) => {
	if(!req.user){
		res.redirect('/auth/login');
	} else {
		next();
	}
}

app.set("view engine",'ejs');

app.use(express.static('./public'));

app.get('/',function(req,res){
	res.render('home' , {user : req.user});
});

app.get('/auth/login',function(req,res){
	res.render('login' , {user : req.user});
});

app.get('/auth/logout',function(req,res){
	req.logout();
	res.redirect('/');
});

app.get('/auth/google', passport.authenticate('google',{
	scope : ['profile']
}));

app.get('/profile', authCheck , function(req,res){
	res.render('profile' , {user : req.user});
});

app.get('/auth/google/redirect', passport.authenticate('google'),function(req,res){
  		res.redirect('/profile',{user : req.user});
});

app.listen('8080');