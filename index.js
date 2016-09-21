var express = require('express');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var User = require('./models/user');
var Message = require('./models/message');
var bcrypt = require('bcryptjs');
var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;

var app = express();

var jsonParser = bodyParser.json();

var strategy = new BasicStrategy(function(username, password, callback) {
    User.findOne({
        "username": username
    }, function(err, user) {
        if (err) {
            return callback(err);
        }
        
        //if the error doesn't exist
        if (!user) {
            return callback(null, false);
        }
        
        user.validatePassword(password, function(err, isValid) {
            if (err) {
                return callback(err);
            }
            
            //if isValid is false
            if (!isValid) {
                return callback(null, false);
            }
            console.log(user);
            return callback(null, user);
        });
    });
});

passport.use(strategy);

app.use(passport.initialize());

//API endpoints for USERS

//returns the list of all users username and hash
app.get('/users', passport.authenticate('basic', {session: false}), function(req, res) {
    User.find({}, function(err, user) { //blank obj means it searches for EVERYTHING
        if (err) {
            return res.status(500).json({message: "Internal server error"});
        }
        res.json(user);
    });
});

app.post('/users', jsonParser, function(req, res) {
    
    var username = req.body.username;
    
    // does req.body.username exist
    if(!username) {
        return res.status(422).json({message: 'Missing field: username'});
    }
    
    // is req.body.username a string
    if(typeof username !== 'string') {
        return res.status(422).json({message: 'Incorrect field type: username'});
    }
    
    username = username.trim(); //gets rid of the white space in username
    
    if(username === ""){
        return res.status(422).json({message: "Incorrect field length: username"});
    }
    
    var password = req.body.password;
    
    // does req.body.password exist
    if(!password) {
        return res.status(422).json({message: 'Missing field: password'});
    }
    
    // is req.body.password a string
    if(typeof password !== 'string') {
        return res.status(422).json({message: 'Incorrect field type: password'});
    }
    
    password = password.trim(); //gets rid of the white space in password
    
    if(password === ""){
        return res.status(422).json({message: "Incorrect field length: password"});
    }
    
    // start bcrypt - genSalt, then hash password, then User.create(etc...)
    bcrypt.genSalt(10, function(err, salt) {
        if (err) {
            return res.status(500).json({message: "Internal server error"});
        }
        
        bcrypt.hash(password, salt, function(err, hash) {
            if (err) {
                return res.status(500).json({message: "Internal server error"});
            }
            
            //more consistent with searches
            User.create({username: username, password: hash}, function(err, user) {
                if (err) {
                    console.error(err);
                    return res.status(500).json({message: "Internal server error"});
                }
                
                res.status(201).location('/users/' + user._id).json({});
            });
        });
    });
});

//returns a username as well as their Id
app.get("/users/:userId", passport.authenticate('basic', {session: false}), function(req, res) {

    var id = req.params.userId;
    User.findOne({_id: id}, function(err, user) {
        if(err) {
            console.error(err);
            return res.sendStatus(500).json({message: "Internal server error"});
        }
        
        if(!user) {
            return res.status(404).json({"message": "User not found"});
        }
        res.status(200).json({"username": user.username, "_id": user._id});
    });
    
});

//change the username / change the password
app.put("/users/:userId", passport.authenticate('basic', {session: false}), jsonParser, function(req, res) {
    var id = req.params.userId;
    var newName = req.body.username;
    var newPassword = req.body.password;
    
    if(!newName) {
        return res.status(422).json({'message': 'Missing field: username'});
    }
    
    if (typeof newName !== 'string') {
        return res.status(422).json({'message': 'Incorrect field type: username'});
    }
    
    if (!newPassword) {
        return res.status(422).json({'message': 'Missing field: password'});
    }
    
    if (typeof newPassword !== 'string') {
        return res.status(422).json({'message': 'Incorrect field type: password'});
    }
    
    //if password exist...
    //start bcrypt - genSalt, then hash password, then User.create(etc...)
    bcrypt.genSalt(10, function(err, salt) {
        if (err) {
            return res.status(500).json({message: "Internal server error"});
        }
        
        bcrypt.hash(newPassword, salt, function(err, hash) {
            if (err) {
                return res.status(500).json({message: "Internal server error"});
            }
            
            if (!(req.user && req.user._id.toString() === id)) { //needed .toString() because req.user._id is an object
                return res.sendStatus(401);
            }
            
            User.findOneAndUpdate({_id: id}, {username: newName, password: hash}, {upsert: true}, function(err, user) { //upsert creates a new object if it doesn't already exists
                if(err) {
                    console.error(err);
                    return res.sendStatus(500).json({message: "Internal server error"});
                }
               return res.status(200).json({});
                
            });
        });
    });
});

app.delete("/users/:userId", passport.authenticate('basic', {session: false}), jsonParser, function(req,res) {
    var id = req.params.userId;
    
    if (!(req.user && req.user._id.toString() === id)) { //needed .toString() because req.user._id is an object
        return res.sendStatus(401);
    }
   
    User.findOneAndRemove({_id: id}, function(err, user) {
    if(err) {
        console.error(err);
        return res.sendStatus(500).json({message: "Internal server error"});
    }
       
    if (!user) {
        return res.status(404).json({'message': 'User not found'});
    }
    
    res.status(200).json({});
   });
});

//API endpoints for MESSAGES

app.get('/messages', passport.authenticate('basic', {session: false}), function(req,res) {
   var messages = [];
   var options = [{path: 'from'}, {path: 'to'}]; 
   var query = req.query;
   
    Message.find(query)
    .populate('from to')
    .exec(function(err,message) {
        return res.status(200).json(message);
    });
});

app.post('/messages', jsonParser, function(req, res) {
    if(!req.body.text) {
           return res.status(422).json({"message": "Missing field: text"});
       }else if(typeof(req.body.text) !== "string") {
           return res.status(422).json({"message": "Incorrect field type: text"});
       }else if(typeof(req.body.to) !== "string") {
           return res.status(422).json({"message": "Incorrect field type: to"});
       }else if(typeof(req.body.from) !== "string") {
           return res.status(422).json({"message": "Incorrect field type: from"});
       }
       console.log(req.body);
      
    User.findOne({ _id: req.body.to }) //checks if query passes(syntax errors only)
        .then(function(user){ 
            //checks if user is found/not
            if (!user) return res.status(422).json({ message: 'Incorrect field value: to'});
            return User.findOne({ _id: req.body.from }); // to continue chain, must return new Promise(check query again)
        })
        .then(function(user) { //chain continues
            if (!user) return res.status(422).json({ message: 'Incorrect field value: from'});
            
           Message.create(req.body, function(err, message) {
               //console.log(message);
               if(err) {
                   console.error(err);
                   return res.sendStatus(500);
               }
                return res.status(201).location("/messages/" + message._id).json({});
           });
        }) //catch runs when there is query runs into an error
        .catch(function(err){
            console.error(err);
            return res.sendStatus(500);
        });
});

app.get("/messages/:messageId", function(req, res) {
    var msgID = req.params.messageId;
    Message
        .findOne({_id: msgID})
        .populate('to from')
        .exec(function(err, message){
            if(err) {
                console.error(err);
                return res.sendStatus(500);
            }
            if(!message) {
                console.log("you're in");
                return res.status(404).json({"message": "Message not found"});   
            }
            console.log(message);
            return res.status(200).json(message);
        });
});

var runServer = function(callback) {
    var databaseUri = process.env.DATABASE_URI || global.databaseUri || 'mongodb://localhost/sup';
    mongoose
        .connect(databaseUri)
        .then(function() {
            console.log('db connected...');
            var port = process.env.PORT || 8080;
            var server = app.listen(port, function() {
                console.log('Listening on localhost:' + port);
                if (callback) {
                    callback(server);
                }
            })
        .catch(function(err){
            console.log(err); 
        });
    });
};

if (require.main === module) {
    runServer();
};

exports.app = app;
exports.runServer = runServer;

