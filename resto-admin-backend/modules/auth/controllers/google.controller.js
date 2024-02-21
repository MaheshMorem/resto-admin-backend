'use strict';
var passport = require('passport');
var TokensCtrl = require('../controllers/tokens.controller');
var HTTP_CODES = require('../../core/controllers/httpcodes.server.controller').CODES;
var config = require('../../../config/config');
var moment = require('moment');
var url = require('url');
const requestIp = require('request-ip');
var _ = require('lodash');
var ShortUniqueId = require('short-unique-id');
const cuid = require('cuid');
var async = require('async');
var AuthCtrl = require('../controllers/auth.controller');
var config = require('../../../config/config');
var UserDbo = require('../dbo/user.dbo');
var UserGraphDbo = require('../dbo/user.graph.dbo');
var AuthDbo = require('../dbo/auth.dbo');
var Parser = require('ua-parser-js');
var HTTP_STATUS_CODES = require('../../core/controllers/httpcodes.server.controller').CODES;
var DeviceDetector = require("device-detector-js");


exports.loginWithOAuthGoogle = function (req, res) {
  passport.authenticate('google', function(err, userData) {

    if(err) {

      const errMsg = req.t('SOMETHING_WENT_WRONG') + ' ' +
        req.t('PLEASE_TRY_AGAIN');
      var responsePayload = {
        message : req.t('facebook:AUTH_CODE_ALREADY_USED')
      };

      if(err.name && err.name == 'TokenError') {
        res.status(
          HTTP_CODES.BAD_REQUEST
        ).json(responsePayload);
      } else if (err.name && err.name == 'UserVerifyError') {
        var query = {error:err.name}
        res.status(
          HTTP_CODES.UNAUTHORIZED
        ).redirect(url.format({
          pathname:config.creatorsWebDomainLoginUrl,
          query:query
        }));
      } else {

        var responsePayload = {
          message : err
        };

        res.status(
          HTTP_CODES.BAD_REQUEST
        ).json(responsePayload);
      }
    }

    const clientIp = requestIp.getClientIp(req); 
    
    // If user doesn't exist --> register user --> then login
    if(!userData.existingUserData.length) {

      var responsePayload = {
        message : req.t('user:NOT_AN_ADMIN')
      };

      return res.status(
        HTTP_STATUS_CODES.UNAUTHORIZED
      ).json(responsePayload);

      // var userObjForRegistration = getRegistrationUserObjFromRawData(userData.userDataFromGoogle);
      // var providerObjForRegistration = getRegistrationProviderObjFromRawData(userData.userDataFromGoogle);

      // async.waterfall([
      //   function registerUser(next) {

      //     UserDbo.registerUser(userObjForRegistration, function (err, registeredUserObj) {
      
      //       if(err) {

      //         var responsePayload = {
      //           message : err.message
      //         };

      //         return res.status(
      //           err.httpStatusCode
      //         ).json(responsePayload);
      //       }
            
      //       return next(null, registeredUserObj); 
      //     });
      //   },
      //   function registerUserProvider(registeredUserObj, next) {

      //     UserDbo.registerUserProvider(providerObjForRegistration, function (err, registeredUserProvider) {
      
      //       if(err) {

      //         var responsePayload = {
      //           message : err.message
      //         };

      //         return res.status(
      //           err.httpStatusCode
      //         ).json(responsePayload);
      //       }
            
      //       var finalRegisteredUserObj = {
      //         registeredUserObj: userObjForRegistration,
      //         registeredUserProvider: providerObjForRegistration
      //       }

      //       return next(null, finalRegisteredUserObj); 
      //     });
      //   },function registerUserNodeOnGraphDb(finalRegisteredUserObj, next) {

      //     // TODO: If somehting happens and graph db throws error
      //     // mysql already stored the user but graph db not stored user yet
      //     // handle the situation
      //     UserGraphDbo.registerUserNodeOnGraphDb(finalRegisteredUserObj, function (err, registeredUserProvider) {
      
      //       if(err) {

      //         var responsePayload = {
      //           message : err.message
      //         };

      //         return res.status(
      //           err.httpStatusCode
      //         ).json(responsePayload);
      //       }

      //       return next(null, finalRegisteredUserObj); 
      //     });
      //   }, function generateLoginTokens(finalRegisteredUserObj, next) {

      //     var userDataForJWT = {
      //       user_id : finalRegisteredUserObj.registeredUserObj.user_id
      //     };
      //     var userId = finalRegisteredUserObj.registeredUserObj.user_id;

      //     TokensCtrl.generateJWTnRefreshTokens(userDataForJWT, function (err, tokenData) {

      //       if(err) {
        
      //         const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
      //         var responsePayload = {
      //           message : errMsg
      //         };

      //         return res.status(
      //           err.httpStatusCode
      //         ).json(responsePayload);
      //       } else {

      //         var userLoginDeviceData = getLoggedInDeviceData(req.headers['user-agent'], req.body);
      //         userLoginDeviceData.userId = userId;
      //         userLoginDeviceData.tokenData = tokenData;
      //         userLoginDeviceData.clientIp = clientIp;

      //         AuthCtrl.registerDeviceNSaveLoginHistory(userLoginDeviceData, function (err, loginDeviceSavedResp) {
        
      //           // DO NOT BOTHER IF THERE IS ANY ERROR FROM DB. WE ARE TRYING TO INSERT DEVICE DATA AND 
      //           // LOGIN HISTORY DATA HERE. RESPONSE IS NOT NEEDED
      //         });
        
      //         var tokenPayload = {
      //           accessToken : tokenData.jwtToken,
      //           refreshToken : tokenData.encryptedRT,
      //           rsid : tokenData.redisRefreshTokenObj.rsid
      //         };

      //         return next(null, tokenPayload)

      //       }
      //     });
      //   }
      // ], function (errObj, finalTokenObject) {
        
      //   if(errObj) {
        
      //     return res.status(
      //       errObj.httpStatusCode
      //     ).json({
      //       message : errObj.message
      //     });
      //   }
    
      //   res.status(
      //     HTTP_STATUS_CODES.OK
      //   ).json(finalTokenObject);
      // });
    } else {

      // If user exists 
      // a) check if email provided from fb and in our db are same
      // b) if same --> login
      // c) if not same --> add this email in our db as secondary email
      // d) then login

      var userEmail = userData.userDataFromGoogle.email;
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

        UserDbo.getAdminUserRoleByUserId(userId,  function (err, adminUserData) {

          if(err) {

            var responsePayload = {
              message : err.message
            };
  
            return res.status(
              err.httpStatusCode
            ).json(responsePayload);
          }

          if(!adminUserData) {

            var responsePayload = {
              message : req.t('user:NOT_AN_ADMIN')
            };
  
            return res.status(
              HTTP_STATUS_CODES.UNAUTHORIZED
            ).json(responsePayload);
          }
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

              res.cookie('accessToken', tokenData.jwtToken, {
                httpOnly : true,
                maxAge : config.jwt.expiresInMilliseconds,
                domain : config.cookieDoman
              }).cookie('refreshToken', tokenData.encryptedRT, {
                httpOnly : true,
                maxAge : config.refreshToken.expiresInMilliseconds,
                domain : config.cookieDoman
              }).cookie('rsid', tokenData.redisRefreshTokenObj.rsid, {
                httpOnly : true,
                maxAge : config.refreshToken.expiresInMilliseconds,
                domain : config.cookieDoman
              }).cookie('sessIat', moment().unix(), {
                httpOnly : true,
                maxAge : config.jwt.expiresInMilliseconds,
                domain : config.cookieDoman
              }).status(
                HTTP_STATUS_CODES.OK
              ).redirect(config.clientUrl);
                
              }
          });
        });
      });
    }
  })(req, res);;
}

exports.loginWithGoogleToken = function (req, res) {
  passport.authenticate('google-token', function(err, userData) {

    if(err) {

      const errMsg = req.t('SOMETHING_WENT_WRONG') + ' ' +
        req.t('PLEASE_TRY_AGAIN');
      var responsePayload = {
        message : req.t('facebook:AUTH_CODE_ALREADY_USED')
      };

      if(err.name && err.name == 'TokenError') {
        res.status(
          HTTP_CODES.BAD_REQUEST
        ).json(responsePayload);
      } else if (err.name && err.name == 'UserVerifyError') {
        var query = {error:err.name}
        res.status(
          HTTP_CODES.UNAUTHORIZED
        ).redirect(url.format({
          pathname:config.creatorsWebDomainLoginUrl,
          query:query
        }));
      } else {

        var responsePayload = {
          message : err
        };

        res.status(
          HTTP_CODES.BAD_REQUEST
        ).json(responsePayload);
      }
    }

    const clientIp = requestIp.getClientIp(req); 

    // If user doesn't exist --> register user --> then login
    if(!userData.existingUserData.length) {

      var userObjForRegistration = getRegistrationUserObjFromRawData(userData.userDataFromGoogle);
      var providerObjForRegistration = getRegistrationProviderObjFromRawData(userData.userDataFromGoogle);

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
        },function registerUserNodeOnGraphDb(finalRegisteredUserObj, next) {

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

              return next(null, tokenPayload)


              // res.cookie('accessToken', tokenData.jwtToken, {
              //   httpOnly : true,
              //   maxAge : config.jwt.expiresInMilliseconds,
              //   domain : config.cookieDomain
              // }).cookie('refreshToken', tokenData.encryptedRT, {
              //   httpOnly : true,
              //   maxAge : config.refreshToken.expiresInMilliseconds,
              //   domain : config.cookieDomain
              // }).cookie('rsid', tokenData.redisRefreshTokenObj.rsid, {
              //   httpOnly : true,
              //   maxAge : config.refreshToken.expiresInMilliseconds,
              //   domain : config.cookieDomain
              // }).cookie('sessIat', moment().unix(), {
              //   httpOnly : true,
              //   maxAge : config.jwt.expiresInMilliseconds,
              //   domain : config.cookieDomain
              // }).status(
              //   HTTP_STATUS_CODES.OK
              // ).redirect(config.creatorsWebDomainUrl);
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

      var userEmail = userData.userDataFromGoogle.email;
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

              return next(null, responsePayload)

              
              // res.cookie('accessToken', tokenData.jwtToken, {
              //   httpOnly : true,
              //   maxAge : config.jwt.expiresInMilliseconds,
              //   domain : config.cookieDomain
              // }).cookie('refreshToken', tokenData.encryptedRT, {
              //   httpOnly : true,
              //   maxAge : config.refreshToken.expiresInMilliseconds,
              //   domain : config.cookieDomain
              // }).cookie('rsid', tokenData.redisRefreshTokenObj.rsid, {
              //   httpOnly : true,
              //   maxAge : config.refreshToken.expiresInMilliseconds,
              //   domain : config.cookieDomain
              // }).cookie('sessIat', moment().unix(), {
              //   httpOnly : true,
              //   maxAge : config.jwt.expiresInMilliseconds,
              //   domain : config.cookieDomain
              // }).status(
              //   HTTP_STATUS_CODES.OK
              // ).redirect(config.creatorsWebDomainUrl);
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
                  
                  // res.cookie('accessToken', tokenData.jwtToken, {
                  //   httpOnly : true,
                  //   maxAge : config.jwt.expiresInMilliseconds,
                  //   domain : config.cookieDomain
                  // }).cookie('refreshToken', tokenData.encryptedRT, {
                  //   httpOnly : true,
                  //   maxAge : config.refreshToken.expiresInMilliseconds,
                  //   domain : config.cookieDomain
                  // }).cookie('rsid', tokenData.redisRefreshTokenObj.rsid, {
                  //   httpOnly : true,
                  //   maxAge : config.refreshToken.expiresInMilliseconds,
                  //   domain : config.cookieDomain
                  // }).cookie('sessIat', moment().unix(), {
                  //   httpOnly : true,
                  //   maxAge : config.jwt.expiresInMilliseconds,
                  //   domain : config.cookieDomain
                  // }).status(
                  //   HTTP_STATUS_CODES.OK
                  // ).redirect(config.creatorsWebDomainUrl);
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
  })(req, res);;
}


function trimUserDataForJWT(user) {

  var userDataForJWT = {
    id : user.id,
    studioId : user.studio_id,
    languageId : user.language_id,
    name : user.name
  }

  return userDataForJWT;
}

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

  return userObj;
}

function getRegistrationProviderObjFromRawData(userDataFromProvider) {

  var providerDataObj = {
    auth_provider_id: cuid(),
    provider_type: 'google',
    user_id_from_provider: userDataFromProvider.user_id_from_provider,
    user_id: userDataFromProvider.user_id
  }

  return providerDataObj;
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

      loginClientDeviceData.brand = device.device.brand

      if(ua.os.name && ua.os.name.toLocaleLowerCase() == 'mac os') {
        
        loginClientDeviceData.model = "MacBook";
      }
    }

    if(!loginClientDeviceData.model || loginClientDeviceData.model == '') {

      var DD = new DeviceDetector();
      var device = DD.parse(ua.ua);

      loginClientDeviceData.model = device.device.model
    }

    userLoginDeviceData = {
      device : loginClientDeviceData,
      os : loginClientUserDeviceData,
      client : loginClientData
    }
  }
  
  return userLoginDeviceData;
}
