var config = require('../../../config/config');
var passport = require('passport');
var path = require('path');

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

config.getGlobbedFiles('./config/lib/passport/strategies/*.js').forEach(function (strategy) {

  require(path.resolve(strategy))();
})
