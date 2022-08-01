require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 16;

///////////////////////Step:1 Using Passport Module////////////////////////
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook"); 

const findOrCreate = require('mongoose-findorcreate');

const app = express();
mongoose.connect("mongodb://localhost:27017/userDB");
app.use(express.static("public"));

app.use(bodyParser.urlencoded({ extended: true }));

app.set("view engine" , "ejs");

///////////////////////Step:2 Using Passport Module////////////////////////

app.use(
  session({
    secret: "This is our Secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});
const User = mongoose.model("User", userSchema);

///////////////////////Step:3 Using Passport Module////////////////////////
passport.use(User.createStrategy());
passport.serializeUser(function(user, done){
    done(null, user.id);
});
passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});
app.set("view engine", "ejs");
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({googleId: profile.id}, function (err, user) {
      return cb(err, user);
    });

  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FACEBOOK,
    clientSecret: process.env.CLIENT_SECRET_FACEBOOK,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({facebookId: profile.id}, function (err, user) {
    return cb(err, user);
    }); 
  }
));

app.get('/auth/facebook',
  passport.authenticate('facebook'));
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook',{ failureRedirect: '/login', failureMessage: true }),
  function(req, res) {
    res.redirect('/secrets');
  });
app.get("/", function (req, res) {
  res.render("home");
});
app.get("/auth/google", 
    passport.authenticate("google", {scope: ["profile"]})
);

app.get("/auth/google/secrets", passport.authenticate("google", {failureRedirect: "/login"}), function(req, res){
    res.redirect("/secrets");
});
app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  User.find({"secret": {$ne : null}}, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        res.render("secrets",{userwithsecrets: foundUser})
      }
    }
  });
  // if (req.isAuthenticated()) {
  //   res.render("secrets");
  // } else {
  //   res.redirect("/login");
  // }
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit",function(req,res){
  const submittedsecret = req.body.secret;
  // console.log(req.user.id);
  User.findById(req.user.id, function(err, founduser){
    if(err){
      console.log(err);
    }else{
      if(founduser){
        founduser.secret = submittedsecret;
        founduser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});
app.post("/register", function (req, res) {
  //   bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
  //     const newuser = new User({
  //       email: req.body.username,
  //       password: hash
  //     });
  //     newuser.save(function (err) {
  //       if (err) {
  //         console.log(err);
  //       } else {
  //         res.render("secrets");
  //       }
  //     });
  //   });

  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", function (req, res) {
  //   const username = req.body.username;
  //   const password =req.body.password;
  //   User.findOne({ email: username }, function (err, foundUser) {
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       if (foundUser) {
  //         bcrypt.compare(password, foundUser.password,function(err, result) {
  //         if(result === true){
  //             res.render("secrets");
  //         }
  //         });
  //       }
  //     }
  //   });

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.logIn(user, function(err){
    if(err){
        console.log(err);
    }else{
        passport.authenticate("local")(req,res, function(){
            res.redirect("/secrets");
        });
    }
  });
});

app.get("/logout", function(req, res){
    req.logOut(function(err){
        if(err){
            console.log(err);
        }else{
            res.redirect("/");
        }
    });
   
});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});
