var request = require('request');
var bcrypt = require('bcrypt-nodejs');

var Users = require('../app/collections/users');
var User = require('../app/models/user');

exports.getUrlTitle = function(url, cb) {
  request(url, function(err, res, html) {
    if (err) {
      console.log('Error reading url heading: ', err);
      return cb(err);
    } else {
      var tag = /<title>(.*)<\/title>/;
      var match = html.match(tag);
      var title = match ? match[1] : url;
      return cb(err, title);
    }
  });
};

var rValidUrl = /^(?!mailto:)(?:(?:https?|ftp):\/\/)?(?:\S+(?::\S*)?@)?(?:(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))|localhost)(?::\d{2,5})?(?:\/[^\s]*)?$/i;

exports.isValidUrl = function(url) {
  return url.match(rValidUrl);
};

/************************************************************/
// Add additional utility functions below
/************************************************************/

exports.checkLogin = function(req, res, next) {

  // if ('/signup' !== req.url && '/login' !== req.url && req.session.username === undefined) {
  //   console.log(req.url, req.session.username);
  //   res.redirect('/login');
  // } else {
  //   next();
  // }
  console.log(req.url, req.session.username);
  if ('/signup' !== req.url && req.session.username === undefined) {
    req.url = '/login';
  }
  next();
};


exports.createOrFind = function(req, res) {
  var username = req.body.username;
  var password = req.body.password;
  new User({ username: username })
  .fetch().then(function(found) {
    if (found) {
      res.redirect('/signup');
    } else {
      bcrypt.genSalt(10, function(err, salt) {
          bcrypt.hash(password, salt, null, function(err, hash) {
              // Store hash in your password DB.
              var user = new User({
                username: username,
                password: hash,
                salt: salt
              });
              user.save().then(function(newUser) {
                Users.add(newUser);
                req.session.username = req.body.username;
                res.redirect('/index')
              });      
          });
      });
    }
  });
};

exports.loginUser = function(req, res) {
  var username = req.body.username;
  var password = req.body.password;
  
  new User({ username: username })
  .fetch().then(function(found) {
    if (found) {
      var salt = found.attributes.salt;
      bcrypt.hash(password, salt, null, function(err, hash) {
        if (hash === found.attributes.password) {
          req.session.username = req.body.username;
          res.redirect('/index');
        } else {
          res.redirect('/login')
        }
      })
    } else {
      res.redirect('/login')
    }
  })
};