'use strict';
var passport = require('passport');

var versionConfig = require('../../version');
var FacebookOAuthCtrl = require('../controllers/facebook.controller');
var GoogleOAuthCtrl = require('../controllers/google.controller');
var TruecallerAuthCtrl = require('../controllers/truecaller.controller');
var AuthMiddleware = require('../middlewares/auth.middleware');
var TokensCtrl = require('../controllers/tokens.controller');
var UsersCtrl = require('../controllers/user.controller');
var EmailAuthCtrl = require('../controllers/email.controller');


module.exports = function (app) {
  
  app.route(
    versionConfig.routePrefix +
    "/firebase"
  ).get(
    function (req, res) {
      res.render('firebase.html');
    }
  );

  // Facebook login with oauth token
  app.route(
    versionConfig.routePrefix +
    "/login/facebook"
  ).get(
    function (req, res) {
      res.render('facebook.html');
    }
  );

  // Google login with oauth token
  app.route(
    versionConfig.routePrefix +
    "/login/google"
  ).get(
    function (req, res) {
      res.render('google.html');
    }
  );
  
  app.route(
    versionConfig.routePrefix +
    "/auth/facebook"
  ).post(
    FacebookOAuthCtrl.loginWithFacebookToken
  );

  // Facebook login oauth urls
  app.route(
    versionConfig.routePrefix +
    "/oauth/facebook"
  ).get(
    passport.authenticate('facebook', { scope : ['email'] })
  );

  app.route(
    versionConfig.routePrefix +
    '/oauth/facebook/callback'
  ).get(
    FacebookOAuthCtrl.loginWithOAuthFacebook
  );

  // Google login oauth urls
  app.route(
    versionConfig.routePrefix +
    "/oauth/google"
  ).get(
    passport.authenticate('google', { scope : ['email'] })
  );

  app.route(
    versionConfig.routePrefix +
    '/oauth/google/callback'
  ).get(
    GoogleOAuthCtrl.loginWithOAuthGoogle
  );
  
  app.route(
    versionConfig.routePrefix +
    "/auth/google"
  ).post(
    GoogleOAuthCtrl.loginWithGoogleToken
  );

  // login with truecaller
  app.route(
    versionConfig.routePrefix +
    "/auth/truecaller"
  ).post(
    TruecallerAuthCtrl.loginWithTruecallerToken
  );

  // refresh jwt tokenand rotate refresh token
  app.route(
    versionConfig.routePrefix +
    '/refresh/tokens'
  ).post(
    AuthMiddleware.hasRTTokenNRsid,
    TokensCtrl.refreshJwtnRotateRT
  );

  app.route(
    versionConfig.routePrefix +
    '/logout'
  ).post(
    AuthMiddleware.hasRTTokenNRsid,
    TokensCtrl.revokeTokensnLogout
  );

  app.route(
    versionConfig.routePrefix +
    '/logout'
  ).get(
    AuthMiddleware.hasRTTokenNRsid,
    TokensCtrl.revokeTokensnLogout
  );

  app.route(
    versionConfig.routePrefix +
    '/me'
  ).get(
    AuthMiddleware.isAuthorizedJWT,
    UsersCtrl.getLoggedInUserData
  );

  app.route(
    versionConfig.routePrefix +
    '/auth/email'
  ).post(
    EmailAuthCtrl.loginWithEmail
  );

};
