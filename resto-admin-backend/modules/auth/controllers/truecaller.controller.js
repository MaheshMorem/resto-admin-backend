'use strict';
var passport = require('passport');
var moment = require('moment');
var url = require('url');
const cuid = require('cuid');
var async = require('async');
var _ = require('lodash');
var Parser = require('ua-parser-js');
var DeviceDetector = require("device-detector-js");
const requestIp = require('request-ip');
var ShortUniqueId = require('short-unique-id');

var TokensCtrl = require('../controllers/tokens.controller');
var HTTP_STATUS_CODES = require('../../core/controllers/httpcodes.server.controller').CODES;
var AuthCtrl = require('../controllers/auth.controller');
var config = require('../../../config/config');
var UserDbo = require('../dbo/user.dbo');
var UserGraphDbo = require('../dbo/user.graph.dbo');
var AuthDbo = require('../dbo/auth.dbo');
const axios = require('axios');


/**
  * @api {get} /v1/auth/facebook Login with Facebook auth code / access token
  * @apiGroup Social Login
  *
  * @apiParam {String} access_token Facebook auth code / access token
  * 
  * @apiSuccess {String} accessToken Access token
  * @apiSuccess {String} refreshToken Refresh token
  * @apiSuccess {String} rsid session id for refresh token
  **/

exports.loginWithTruecallerToken = async function (req, res) {

  let userData = {};
  const userAccessToken = req.body.access_token;

  // Retrieve the user's information from Facebook
  const userInfoUrl = `https://profile4-noneu.truecaller.com/v1/default`;
  const headers = {
    Authorization: `Bearer ${userAccessToken}`
  };

  const userInfoResponse = await axios.get(userInfoUrl, { headers });
  const userInfo = userInfoResponse.data;

  const userDataFromTc = restructureTruecallerData(userInfo);

  userData.userDataFromTc = userDataFromTc;

  const clientIp = requestIp.getClientIp(req); 

  AuthDbo.getUserDataByProviderBackedUserId(
    userDataFromTc.user_id_from_provider, function (err, existingUserData) {

    if(err) {

      return done(err);
    }

    userData.existingUserData = existingUserData;

    if(!userData.existingUserData.length) {

      var userObjForRegistration = getRegistrationUserObjFromRawData(userData.userDataFromTc);
      var providerObjForRegistration = getRegistrationProviderObjFromRawData(userData.userDataFromTc);
  
      async.waterfall([
        function registerUser(next) {
  
          UserDbo.registerUser(userObjForRegistration, function (err, registeredUserObj) {
  
            if(err) {
  
              var responsePayload = {
                message : err.message
              };
  
              return res.status(
                err.httpStatusCode
              ).json(responsePayload);
            }
  
            return next(null, registeredUserObj); 
          });
        },
        function registerUserProvider(registeredUserObj, next) {
  
          UserDbo.registerUserProvider(providerObjForRegistration, function (err, registeredUserProvider) {
  
            if(err) {
  
              var responsePayload = {
                message : err.message
              };
  
              return res.status(
                err.httpStatusCode
              ).json(responsePayload);
            }
  
            var finalRegisteredUserObj = {
              registeredUserObj: userObjForRegistration,
              registeredUserProvider: providerObjForRegistration
            }
  
            return next(null, finalRegisteredUserObj); 
          });
        }, function registerUserNodeOnGraphDb(finalRegisteredUserObj, next) {
  
          // TODO: If somehting happens and graph db throws error
          // mysql already stored the user but graph db not stored user yet
          // handle the situation
          UserGraphDbo.registerUserNodeOnGraphDb(finalRegisteredUserObj, function (err, registeredUserProvider) {
  
            if(err) {
  
              var responsePayload = {
                message : err.message
              };
  
              return res.status(
                err.httpStatusCode
              ).json(responsePayload);
            }
  
            return next(null, finalRegisteredUserObj); 
          });
        }, function generateLoginTokens(finalRegisteredUserObj, next) {
  
          var userDataForJWT = {
            user_id : finalRegisteredUserObj.registeredUserObj.user_id
          };
          var userId = finalRegisteredUserObj.registeredUserObj.user_id;
  
          TokensCtrl.generateJWTnRefreshTokens(userDataForJWT, function (err, tokenData) {
  
            if(err) {
  
              const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
              var responsePayload = {
                message : errMsg
              };
  
              return res.status(
                err.httpStatusCode
              ).json(responsePayload);
            } else {
  
              var userLoginDeviceData = getLoggedInDeviceData(req.headers['user-agent'], req.body);
              userLoginDeviceData.userId = userId;
              userLoginDeviceData.tokenData = tokenData;
              userLoginDeviceData.clientIp = clientIp;
  
              AuthCtrl.registerDeviceNSaveLoginHistory(userLoginDeviceData, function (err, loginDeviceSavedResp) {
  
                // DO NOT BOTHER IF THERE IS ANY ERROR FROM DB. WE ARE TRYING TO INSERT DEVICE DATA AND 
                // LOGIN HISTORY DATA HERE. RESPONSE IS NOT NEEDED
              });
  
              var tokenPayload = {
                accessToken : tokenData.jwtToken,
                refreshToken : tokenData.encryptedRT,
                rsid : tokenData.redisRefreshTokenObj.rsid
              };
  
              return next(null, tokenPayload);
            }
          });
        }
      ], function (errObj, finalTokenObject) {
  
        if(errObj) {
  
          return res.status(
            errObj.httpStatusCode
          ).json({
            message : errObj.message
          });
        }
  
        res.status(
          HTTP_STATUS_CODES.OK
        ).json(finalTokenObject);
      });
    } else {
  
      // If user exists 
      // a) check if email provided from fb and in our db are same
      // b) if same --> login
      // c) if not same --> add this email in our db as secondary email
      // d) then login
  
      var userEmail = userData.userDataFromTc.email;
      var userId = userData.existingUserData[0].user_id;
      var options = {
        select : ['email', 'user_id']
      };
  
      AuthDbo.getUserDataByEmail(userEmail, options, function (err, loggedInUserData) {
  
        if(err) {
  
          var responsePayload = {
            message : err.message
          };
  
          return res.status(
            err.httpStatusCode
          ).json(responsePayload);
        }

        // This email exists -> not a new email
        if(loggedInUserData.length) {
  
          var userDataForJWT = {
            user_id : userId
          };
  
          TokensCtrl.generateJWTnRefreshTokens(userDataForJWT, function (err, tokenData) {
  
            if(err) {
  
              const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
              var responsePayload = {
                message : errMsg
              };
  
              res.status(
                HTTP_STATUS_CODES.BAD_REQUEST
              ).json(responsePayload);
            } else {
  
              var userLoginDeviceData = getLoggedInDeviceData(req.headers['user-agent'], req.body);
              userLoginDeviceData.userId = userId;
              userLoginDeviceData.tokenData = tokenData;
              userLoginDeviceData.clientIp = clientIp;
  
              AuthCtrl.registerDeviceNSaveLoginHistory(userLoginDeviceData, function (err, loginDeviceSavedResp) {
  
                // DO NOT BOTHER IF THERE IS ANY ERROR FROM DB. WE ARE TRYING TO INSERT DEVICE DATA AND 
                // LOGIN HISTORY DATA HERE. RESPONSE IS NOT NEEDED
              });
  
              var responsePayload = {
                accessToken : tokenData.jwtToken,
                refreshToken : tokenData.encryptedRT,
                rsid : tokenData.redisRefreshTokenObj.rsid
              };
  
              res.status(
                HTTP_STATUS_CODES.OK
              ).json(responsePayload);
            }
          });
        } else {
  
          // This email does not exist -> new email
          async.waterfall([
            function registerSecondaryEmail(next) {
  
              var rawDataForSecondayEmail = {
                email : userEmail,
                user_id : userId
              }
  
              var secondaryEmailObj = getSecondaryEmailData(rawDataForSecondayEmail)
  
              UserDbo.registerSecondaryEmail(secondaryEmailObj, function (err, registeredUserProvider) {
  
                // DO NOT BOTHER IF THERE IS ANY ERROR FROM DB. WE ARE JUST TRYING TO INSERT NEW EMAIL
                // ONLY IF EMAIL DOES NOT EXIST. WHEN THIS EMAIL IS ALREADY EXISTS ON DB
                // DB THROWS DUP_ENTRY ERROR. WE DO NOT NEED TO HANDLE IT SPECIFICALLY
  
                return next(null); 
              });
            }, function (next) {
  
              var userDataForJWT = {
                user_id : userId
              };
  
              TokensCtrl.generateJWTnRefreshTokens(userDataForJWT, function (err, tokenData) {
  
                if(err) {
  
                  const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
                  var responsePayload = {
                    message : errMsg
                  };
  
                  return res.status(
                    HTTP_STATUS_CODES.BAD_REQUEST
                  ).json(responsePayload);
                } else {
  
                  var userLoginDeviceData = getLoggedInDeviceData(req.headers['user-agent'], req.body);
                  userLoginDeviceData.userId = userId;
                  userLoginDeviceData.tokenData = tokenData;
                  userLoginDeviceData.clientIp = clientIp;
  
                  AuthCtrl.registerDeviceNSaveLoginHistory(userLoginDeviceData, function (err, loginDeviceSavedResp) {
  
                    // DO NOT BOTHER IF THERE IS ANY ERROR FROM DB. WE ARE TRYING TO INSERT DEVICE DATA AND 
                    // LOGIN HISTORY DATA HERE. RESPONSE IS NOT NEEDED
                  });
  
                  var tokenPayload = {
                    accessToken : tokenData.jwtToken,
                    refreshToken : tokenData.encryptedRT,
                    rsid : tokenData.redisRefreshTokenObj.rsid
                  };
  
                  return next(null, tokenPayload);
                }
              });
            }
          ], function (errObj, tokenPayload) {
  
            if(errObj) {
  
              return res.status(
                errObj.httpStatusCode
              ).json({
                message : errObj.message
              });
            }
  
            res.status(
              HTTP_STATUS_CODES.OK
            ).json(tokenPayload);
          });
        }
      });
    }
  });
};

function getRegistrationUserObjFromRawData(userDataFromProvider) {
  
  // generate username, username = 9 digit user id
  // TODO: Change username generation to either manual or figure out a way
  var newId = new ShortUniqueId({ 
    length: 9,
    dictionary: 'number' 
  });
  
  var userObj = _.cloneDeep(userDataFromProvider);
  delete userObj.user_id_from_provider;
  userObj.username = newId();
  userObj.display_name = (userObj.first_name)? userObj.first_name : '';
  userObj.display_name = (userObj.last_name)? userObj.first_name + ' ' + userObj.last_name : userObj.display_name;

  return userObj;
}

function restructureTruecallerData(profile) {
  var user = {
    user_id : cuid(),
    status : 'active',
    created_at : moment().format(config.moment.dbFormat),
    updated_at : moment().format(config.moment.dbFormat)
  };

  // user id from provider database
  if (profile.id) {

    user.user_id_from_provider = profile.id
  }

  if (profile.phoneNumbers && profile.phoneNumbers.length) {

    user.mobile = profile.phoneNumbers[0];
  }

  if (profile.name) {

    if (profile.name.first) {

      user.first_name = profile.name.first;
    } else if (profile.name.last) {

      user.last_name = profile.name.last;
    }

    if (profile.name.first && profile.name.last) {

      user.display_name = profile.name.fist + ' ' + profile.name.last;
    }
  }

  if (profile.onlineIdentities && profile.onlineIdentities.email) {

    user.email = profile.onlineIdentities.email;
    user.is_email_verified = true;
  }

  // user profile pic
  if (profile.avatarUrl) {

    user.profile_pic = profile.avatarUrl;
  }

  if (profile.gender) {

    user.gender = profile.gender.toLowerCase();
  }

  return userData;
}

function getRegistrationProviderObjFromRawData(userDataFromProvider) {

  var providerDataObj = {
    auth_provider_id: cuid(),
    provider_type: 'truecaller',
    user_id_from_provider: userDataFromProvider.user_id_from_provider,
    user_id: userDataFromProvider.user_id
  }

  return providerDataObj;
}

function getSecondaryEmailData(rawData) {

  var secondaryEmailObj = {
    user_se_id: cuid(),
    email: rawData.email,
    user_id: rawData.user_id
  }

  return secondaryEmailObj;
}

function getLoggedInDeviceData(userAgenet, payload) {
  
  var userLoginDeviceData = {};
  
  if(payload.deviceData) {

    var deviceData = payload.deviceData;

    userLoginDeviceData.device = {
      model : deviceData.model,
      brand : deviceData.brand
    }

    userLoginDeviceData.os = {
      os : deviceData.os,
      os_version : deviceData.os_version
    }

    userLoginDeviceData.client = {
      client_type : deviceData.client_type,
      client_version : deviceData.client_version,
      client_major : deviceData.client_major,
      client_ua : deviceData.client_ua,
      client_engine : deviceData.client_engine
    }
  } else {

    var ua = Parser(userAgenet);

    var loginClientDeviceData = {
      brand : ua.device.vendor,
      model : ua.device.model
    };

    var loginClientUserDeviceData = {
      os : ua.os.name,
      os_version : ua.os.version
    };

    var loginClientData = {
      client_type : 'browser',
      client_version : ua.browser.version,
      client_major : ua.browser.major,
      client_ua : ua.ua,
      client_engine : ua.engine
    };

    if(!loginClientDeviceData.brand || loginClientDeviceData.brand == '') {

      var DD = new DeviceDetector();
      var device = DD.parse(ua.ua);

      if(device && device.device && device.device.brand) loginClientDeviceData.brand = device.device.brand

      if(ua.os.name && ua.os.name.toLocaleLowerCase() == 'mac os') {
        
        loginClientDeviceData.model = "MacBook";
      }
    }

    if(!loginClientDeviceData.model || loginClientDeviceData.model == '') {

      var DD = new DeviceDetector();
      var device = DD.parse(ua.ua);

      if(device && device.device && device.device.model) loginClientDeviceData.model = device.device.model
    }

    userLoginDeviceData = {
      device : loginClientDeviceData,
      os : loginClientUserDeviceData,
      client : loginClientData
    }
  }
  
  return userLoginDeviceData;
}