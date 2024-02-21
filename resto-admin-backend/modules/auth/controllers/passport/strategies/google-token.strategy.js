var passport = require('passport');
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var moment = require('moment');
var config = require('../../../../../config/config');
var cuid = require('cuid');
var versionConfig = require('../../../../version');
var AuthDbo = require('../../../dbo/auth.dbo');


module.exports = function () {

  var callbackURL =  config.exposedDomainUrl + versionConfig.routePrefix +
    config.google.callbackURL;

  passport.use(
    new GoogleStrategy({
        clientID: config.google.clientID,
        clientSecret: config.google.clientSecret,
        callbackURL: callbackURL,
        passReqToCallback : true
      }, function(req, token, tokenSecret, profile, done) {

        var userDataFromGoogle = restructureGoogleData(profile);

        AuthDbo.getUserDataByProviderBackedUserId(
          userDataFromGoogle.user_id_from_provider, function (err, existingUserData) {

          if(err) {

            return done(err);
          }
          
          return done(null, {
            userDataFromGoogle: userDataFromGoogle,
            existingUserData: existingUserData
          })
        });
      }
    )
  );
}

function restructureGoogleData(profile) {
  var user = {
    user_id : cuid(),
    display_name: "Guest",
    created_at : moment().format(config.moment.dbFormat),
    updated_at : moment().format(config.moment.dbFormat)
  };

  if(profile._json) {
    var userProfileData = profile._json;

    // user name
    if(userProfileData.name) {
      user.display_name = userProfileData.name;
    }

    if(userProfileData.first_name) {
      user.first_name = userProfileData.first_name;
      user.display_name = userProfileData.first_name;
    }

    if(userProfileData.last_name) {
      user.last_name = userProfileData.last_name;
    } 

    if(userProfileData.first_name &&
      userProfileData.last_name) {
      user.display_name = userProfileData.first_name + " " +
        userProfileData.last_name;
    }

    if(userProfileData.short_name) {
      user.first_name = userProfileData.displayName;
      user.display_name = userProfileData.displayName;
    } 
    
    if (profile.displayName) {
      user.first_name = userProfileData.displayName;
      user.display_name = userProfileData.displayName;
    }

    // user email
    if(userProfileData.email) {
      user.email = userProfileData.email;
    } else if (userProfileData.id) {
      user.email = userProfileData.id + '@brochill.com';
    } else if(userProfileData.name) {
      user.email = userProfileData.name.toLowerCase() +
        Date.now() + '@brochill.com';
    } else {
      user.email = Date.now() + '@brochill.com';
    }
  } else {
    if(profile.name && profile.name.givenName &&
      profile.name.familyName) {

        user.name = profile.name.givenName + " " +
          profile.name.familyName;
    } else if(profile.displayName) {
        user.name = profile.displayName;
    } else {
      user.name = "Guest"
    }

    // user email
    if(profile.emails && profile.emails.length &&
        profile.emails[0].value) {
      user.email = profile.emails[0].value;
    } else if (profile.id) {
      user.email = profile.id + '@brochill.com';
    } else if(user.name) {
      user.email = user.name.toLowerCase() +
        Date.now() + '@brochill.com';
    } else {
      user.email = Date.now() + '@brochill.com';
    }
  }

  // user id from provider database
  if (userProfileData.sub) {

    user.user_id_from_provider = userProfileData.sub
  }

  // user profile photo
  if(profile.photos &&
    profile.photos.length &&
    profile.photos[0].value) {

    user.profile_pic = profile.photos[0].value;
  }

  return user;
}
