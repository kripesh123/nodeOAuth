var LocalStrategy       = require('passport-local').Strategy;
var FacebookStrategy    = require('passport-facebook').Strategy;
var TwitterStrategy     =require('passport-twitter').Strategy;
var GoogleStrategy      =require('passport-google-oauth').OAuth2Strategy;


// load up the user model
var User       		= require('../app/models/user');

// load the auth variables
var configAuth = require('./auth');


module.exports = function(passport) {

	
    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

   
    passport.use('local-login', new LocalStrategy({
        
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true 
    },
    function(req, email, password, done) { 
        if(email)
            email=email.toLowerCase();
        
        // asynchronous
        process.nextTick(function(){
            User.findOne({ 'local.email' :  email }, function(err, user) {
                // if there are any errors, return the error before anything else
                if (err)
                    return done(err);

                // if no user is found, return the message
                if (!user)
                    return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash

                // if the user is found but the password is wrong
                if (!user.validPassword(password))
                    return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata

                // all is well, return successful user
                return done(null, user);
            });
        });        
    }));

    passport.use('local-signup',new LocalStrategy({
        usernameField:'email',
        passwordField:'password',
        passReqToCallback:true
    },
    function(req,email,password,done){
        if(email)
            email=email.toLowerCase();
        process.nextTick(function(){
            if(!req.user){
                User.findOne({'local.email':email},function(error,user){
                    if(error)
                        return done(error);
                    if(user){
                        return done(null,false,req.flash('signupMessage','This email is already exist.'));
                    }else{
                        var newUser = new User();
                        newUser.local.email=email;
                        newUser.local.password=newUser.generateHash(password);

                        newUser.save(function(error){
                            if(error)
                                return done(error);
                            return done(null,newUser);
                        });
                    }
                });
            }else if(!req.user.local.email){
                User.findOne({'local.email':email},function(error,user){
                    if(error)
                        return done(error);
                    if(user){
                        return done(null.false,req.flash('loginMessage','This email is already exist in our database'));
                    }else{
                        var user=req.user;
                        user.local.email=email;
                        user.local.password=user.generateHash(password);
                        user.save(function(error){
                            if(error)
                                return done(error);
                            return done(null,user);
                        });
                    }
                }); 
            }else{
                return done(null,req.user);
            }
        });
    }));

    // =========================================================================
    // FACEBOOK ================================================================
    // =========================================================================
    passport.use(new FacebookStrategy({

        
        clientID        : configAuth.facebookAuth.clientID,
        clientSecret    : configAuth.facebookAuth.clientSecret,
        callbackURL     : configAuth.facebookAuth.callbackURL,
        profileFields   :['id','name','email'],
        passReqToCallback:true
    },

    
    function(req, token, refreshToken, profile, done) {

        // asynchronous
        process.nextTick(function() {
            if(!req.user){
                User.findOne({'facebook.id':profile.id},function(error,user){
                    if(error)
                        return done(error);

                    if(user){
                        if(!user.facebook.token){
                            user.facebook.token=token;
                            user.facebook.name=profile.name.givenName + ' ' + profile.name.familyName;
                            user.facebook.email=(profile.emails[0].value || '').toLowerCase();

                            user.save(function(error){
                                if(error)
                                    return done(error);
                                return done(null,user);
                            });
                        }
                        return done(null,user);
                    }else{
                        var newUser=new User();

                        newUser.facebook.id     =profile.id;
                        newUser.facebook.token  =token;
                        newUser.facebook.name   =profile.name.givenName + ' ' + profile.name.familyName;
                        newUser.facebook.email  =(profile.emails[0].value || '').toLowerCase();

                        newUser.save(function(error){
                            if(error)
                                return done(error);
                            return done(null,newUser);
                        });
                    }
                });
            }else{
                var user = req.user;
                user.facebook.id    =profile.id;
                user.facebook.token =token;
                user.facebook.name  =profile.name.givenName + ' ' + profile.name.familyName;
                user.facebook.email =(profile.emails[0].value || '').toLowerCase();

                user.save(function(error){
                    if(error)
                        return done(error)

                    return done(null,user);
                });
            }
        });
    }));
    // =========================================================================
    // TWITTER ================================================================
    // =========================================================================

    passport.use(new TwitterStrategy({
        consumerKey         :configAuth.twitterAuth.consumerKey,
        consumerSecret      :configAuth.twitterAuth.consumerSecret,
        callbackURL         :configAuth.twitterAuth.callbackURL,
        passReqToCallback   :true
    },
    function(req,token,tokenSecret,profile,done){

        process.nextTick(function(){

            if(!req.user){
                User.findOne({'twitter.id':profile.id},function(error,user){
                    if(error)
                        return done(error);

                    if(user){
                        if(!user.twitter.token){
                            user.twitter.token      =token;
                            user.twitter.username   =profile.username;
                            user.twitter.displayName=profile.displayName;

                            user.save(function(error){
                                if(error)
                                    return done(error);
                                return done(null,user);
                            });
                        }
                        return done(null,user);
                    }else{
                        var newUser              =new User();
                        newUser.twitter.id       =profile.id;
                        newUser.twitter.token    =token;
                        newUser.twitter.username =profile.username;
                        newUser.twitter.displayName=profile.displayName;

                        newUser.save(function(error){
                            if(error)
                                return done(error);
                            return done(null,newUser);
                        })
                    }
                });
            }else{
                var user            =req.user;
                user.twitter.id       =profile.id;
                user.twitter.token    =token;
                user.twitter.username =profile.username;
                user.twitter.displayName=profile.displayName;

                user.save(function(error){
                    if(error)
                        return done(error);
                    return done(null,user);
                });
            }
        });
    }));

    //GOOGLE

    passport.use(new GoogleStrategy({
        clientID        :configAuth.googleAuth.clientID,
        clientSecret    :configAuth.googleAuth.clientSecret,
        callbackURL     :configAuth.googleAuth.callbackURL,
        passReqToCallback:true
    },
    function(req,token,refreshToken,profile,done){

        process.nextTick(function(){
            if(!req.user){
                User.findOne({'google.id':profile.id},function(error,user){
                    if(error)
                        return done(error);
                    if(user){
                        if(!user.google.token){
                            user.google.token =token;
                            user.google.name  =profile.displayName;
                            user.google.email =(profile.emails[0].value).toLowerCase();

                            user.save(function(error){
                                if(error)
                                    return done(error);

                                return done(null,user);
                            });
                        }
                        return done(null,user);
                    }else{
                        var newUser             =new User();
                        newUser.google.id    =profile.id
                        newUser.google.token =token;
                        newUser.google.name  =profile.displayName;
                        newUser.google.email =(profile.emails[0].value).toLowerCase();

                        newUser.save(function(error){
                            if(error)
                                return done(error);

                            return done(null,newUser);
                        });
                    }
                });
            }else{
                var user            =req.user;
                user.google.id    =profile.id;
                user.google.token =token;
                user.google.name  =profile.displayName;
                user.google.email =(profile.emails[0].value).toLowerCase();

                user.save(function(error){
                    if(error)
                        return done(error);
                    return done(null,user);
                });
            }
        });
    }));
};