const redis = require('../../../config/lib/redis')
const config = require('../../../config/config')
var jwtCtrl = require('../controllers/jwt.controller');
var refreshTokenCtrl = require('./refreshToken.controller');
var AES256GCM = require('../controllers/aes-gcm.contorller').aes256gcm;
var HTTP_STATUS_CODES = require('../../core/controllers/httpcodes.server.controller').CODES;

var _ = require('lodash');
var i18next = require('i18next');
const cuid = require('cuid');
const moment = require('moment');
const bcrypt = require('bcrypt');
const async = require('async');


var generateJWTnRefreshTokens = function (userDataForJWT, options, next) {

  if(_.isFunction(options) && !next) {

    // set next value as second param
    // sometimes you don't pass options
    next = options;
    options = {};
  }

  var finalTokenObj = {};

  async.waterfall([
    function generateJWTToken(callback) {

      //generate JWT token
      jwtCtrl.generateToken(userDataForJWT, function(jwtToken) {

        finalTokenObj.jwtToken = jwtToken
        callback(null);
      });
    }, function generateRefreshToken(callback) {

      //generate refresh token
      refreshTokenCtrl.generateToken(userDataForJWT, function(refreshToken) {

        finalTokenObj.refreshToken = refreshToken
        callback(null);
      });
    }, function generateRTHash(callback) {

      //generate hash of refresh token
      generateBcryptHash(finalTokenObj.refreshToken, function (err, hashedRT) {

        if(err) {
          const errMsg = req.t('HASH_FAILED') + ' ' +
            req.t('PLEASE_TRY_AGAIN');
  
          callback({
            message : errMsg
          });
        }

        finalTokenObj.hashedRefreshToken = hashedRT;
        callback(null);
      });
    }, function (callback) {

      // generate new RT obj  { rt: <>, p: <>} where rt is real rt and
      // p is parent of that rt then encrypt this json obj with aes256gcm
      // for better seceurity
      var parentRT = 0;
      
      if(options.isRotateRT) {
        parentRT = options.parentRT;
      }

      var refreshTokenObjStringfied = JSON.stringify({
        refreshToken : finalTokenObj.hashedRefreshToken,
        p : parentRT
      });
      
      var encryptedGcmObj = AES256GCM.encrypt(refreshTokenObjStringfied);

      finalTokenObj.iv = encryptedGcmObj.iv;

      // tag aes gcm tag at the end of encrypted data just for future ref
      // gcm auth tag is not to be secured in any db. it can be tagged along 
      // with encrypted data as per it's specs
      finalTokenObj.encryptedRT = encryptedGcmObj.encryptedCipher + 
        "." + encryptedGcmObj.gcmAuthTag;

      callback(null);
    }, function generateRedisRTObj(callback) {

      // generate redis refresh token obj - to store rt data 
      // and compare when generating new RT and AT
      if(options.isRotateRT) {
        generateRedisRefreshTokenObj(
          finalTokenObj.jwtToken,
          options.parentRT,
          finalTokenObj.iv,
          userDataForJWT, function (err, redisRefreshTokenObj) {
  
            if(err) {

              const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
  
              callback({
                message : errMsg
              });
            }
  
            finalTokenObj.redisRefreshTokenObj = redisRefreshTokenObj;
            callback(null);
        });
      } else {

        generateRedisRefreshTokenObj(
          finalTokenObj.jwtToken,
          finalTokenObj.hashedRefreshToken,
          finalTokenObj.iv,
          userDataForJWT, function (err, redisRefreshTokenObj) {
  
            if(err) {

              const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
  
              callback({
                message : errMsg
              });
            }
  
            finalTokenObj.redisRefreshTokenObj = redisRefreshTokenObj;
            callback(null);
        });
      }
    }, function updateRTObjInRedis(callback) {

      if(options.isRotateRT) {

        // update existing token as revoked
        var newRTData = {
          refreshToken : options.parentRT,
          rsid : options.parentTokenRsid,
          isRevoked : true,
          revokedAt : moment().format(config.moment.dbFormat)
        }

        redis.updateRefreshTokenData(
          newRTData, function (err, result) {

            if(err) {
              callback({
                message : err
              });
            }
          });
      }

      // save redis rt object in redis for future ref and set exp in redis store
      // exp time is same as jwt rt exp time
      redis.saveRefreshToken(
        finalTokenObj.redisRefreshTokenObj, function (err, result) {

          if(err) {

            callback({
              message : err
            });
          }
          
          callback(null, finalTokenObj);
        });
    }
  ], function (err, finalResultObj) {

    if(err) {

      const errMsg = i18next.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');

      return next(err);
    }

    next(null, finalResultObj);
  });
}
exports.generateJWTnRefreshTokens = generateJWTnRefreshTokens;


/**
  * @api {post} /v1/refresh/tokens Refresh JWT Token and Rotate refresh token
  * @apiGroup Authentication
  *
  * @apiParam {String} accessToken JWT token
  * @apiParam {String} refreshToken Refresh token
  * @apiParam {String} rsid Session id for refresh token
  *
  * @apiSuccess {String} accessToken Access token
  * @apiSuccess {Object} refreshToken Refresh token
  * @apiSuccess {String} rsid session id for refresh token
  **/

exports.refreshJwtnRotateRT = function (req, res) {

  var refreshToken = (req.cookies.refreshToken) ? req.cookies.refreshToken : null;
  var rsid = (req.cookies.rsid) ? req.cookies.rsid : null;

  if (req.headers.authorization) {

    refreshToken = (req.body.refreshToken) ? req.body.refreshToken : undefined;

    rsid = (req.body.rsid) ? req.body.rsid : undefined;
  }

  // var finalTokenObj = {
  //   at: accessToken,
  //   rt: refreshToken,
  //   rsid: rsid,
  //   sessIat: sessIat
  // };

  var finalTokenObj = {};

  async.waterfall([
    function (callback) {

      redis.getRefreshTokenData(rsid, function (err, redisRefreshTokenData) {

        if(err) {
          const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
      
          return callback({
            message : errMsg,
            httpCode : HTTP_STATUS_CODES.BAD_REQUEST
          });
        }

        if(!redisRefreshTokenData || redisRefreshTokenData == null) {
          const errMsg = req.t('INVALID_RT');
      
          return callback({
            message : errMsg,
            httpCode : HTTP_STATUS_CODES.UNAUTHORIZED
          });
        } else if (redisRefreshTokenData.isRevoked || 
          redisRefreshTokenData.isRevoked == true ||
          redisRefreshTokenData.isLoggedOut ||
          redisRefreshTokenData.isLoggedOut == true) {

          const errMsg = req.t('TOKEN_ALREADY_USED');
      
          return callback({
            message : errMsg,
            httpCode : HTTP_STATUS_CODES.FORBIDDEN
          });
        }

        finalTokenObj.redisRefreshTokenData = redisRefreshTokenData;
        return callback(null);
      });
    }, function (callback) {

      if((!finalTokenObj.redisRefreshTokenData ||
        finalTokenObj.redisRefreshTokenData == null) ||

        (!finalTokenObj.redisRefreshTokenData.accessToken ||
        finalTokenObj.redisRefreshTokenData.accessToken == null) ||

        (!finalTokenObj.redisRefreshTokenData.refreshToken ||
        finalTokenObj.redisRefreshTokenData.refreshToken == null) ||

        (!finalTokenObj.redisRefreshTokenData.iv ||
        finalTokenObj.redisRefreshTokenData.iv == null)) {
          const errMsg = req.t('INVALID_RT');
      
          callback({
            message : errMsg,
            httpCode : HTTP_STATUS_CODES.UNAUTHORIZED
          });
      } else {

        getRTFromEncryptedToken(
          refreshToken,
          finalTokenObj.redisRefreshTokenData.iv,
          function name(err, decryptedRT) {
            if(err) {
              const errMsg = req.t('INVALID_RT');
          
              callback({
                message : errMsg,
                httpCode : HTTP_STATUS_CODES.UNAUTHORIZED
              });
            }
  
            callback(null, decryptedRT);
          }
        );
      }
    }, function (decryptedRT, callback) {

      var decryptedRTObj = JSON.parse(decryptedRT);
      var rtToCheckInDb = (decryptedRTObj.p == 0 || decryptedRTObj.p == '0') ?
        decryptedRTObj.refreshToken : decryptedRTObj.p;
      finalTokenObj.rtToCheckInDb = rtToCheckInDb;

      compareBcryptHash(
        rtToCheckInDb, 
        finalTokenObj.redisRefreshTokenData.refreshToken,
        function name(err, isMatched) {
          if(err) {
            const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
        
            callback({
              message : errMsg,
              httpCode : HTTP_STATUS_CODES.BAD_REQUEST
            });
          }

          finalTokenObj.isRTFound = isMatched;
          callback(null);
        });
    }, function (callback) {

      if(!finalTokenObj.isRTFound) {
        const errMsg = req.t('UNAUTHORIZED');
        
        callback({
          message : errMsg,
          httpCode : HTTP_STATUS_CODES.UNAUTHORIZED
        });
      } else {
        
        var user = {
          user_id : finalTokenObj.redisRefreshTokenData.userId
        };

        var options = {
          isRotateRT : true,
          parentTokenRsid : finalTokenObj.redisRefreshTokenData.rsid,
          parentRT : finalTokenObj.rtToCheckInDb
        };

        generateJWTnRefreshTokens(user, options, function (err, newTokensData) {
          if(err) {
            const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
        
            callback({
              message : errMsg,
              httpCode : HTTP_STATUS_CODES.BAD_REQUEST
            });
          }

          callback(null, newTokensData)
        });
      }
    }
  ], function (errObj, newTokensObj) {
    if(errObj) {
      
      return res.status(
        errObj.httpCode
      ).json({
        message : errObj.message
      });
    } else {

      var responsePayload = {
        accessToken : newTokensObj.jwtToken,
        refreshToken : newTokensObj.encryptedRT,
        rsid : newTokensObj.redisRefreshTokenObj.rsid
      };

      // res.status(
      //   HTTP_STATUS_CODES.OK
      // ).json(responsePayload);

      return res.status(
        HTTP_STATUS_CODES.OK
      ).cookie('accessToken', newTokensObj.jwtToken, {
        httpOnly : true,
        maxAge : config.jwt.expiresInMilliseconds,
        domain : config.cookieDomain
      }).cookie('refreshToken', newTokensObj.encryptedRT, {
        httpOnly : true,
        maxAge : config.refreshToken.expiresInMilliseconds,
        domain : config.cookieDomain
      }).cookie('rsid', newTokensObj.redisRefreshTokenObj.rsid, {
        httpOnly : true,
        maxAge : config.refreshToken.expiresInMilliseconds,
        domain : config.cookieDomain
      }).cookie('sessIat', moment().unix(), {
        httpOnly : true,
        maxAge : config.jwt.expiresInMilliseconds,
        domain : config.cookieDomain
      }).json(responsePayload);
    }
  });
}


/**
  * @api {post} /v1/logout Revoke JWT and refresh tokens and do logout
  * @apiGroup Authentication
  *
  * @apiParam {String} accessToken JWT token
  * @apiParam {String} refreshToken Refresh token
  * @apiParam {String} rsid Session id for refresh token
  *
  * @apiSuccess {String} messsage Logout successful 
  **/
exports.revokeTokensnLogout = function (req, res) {

  var accessToken = (req.cookies.accessToken) ? 
    req.cookies.accessToken : undefined;

  var refreshToken = (req.cookies.refreshToken) ? 
  req.cookies.refreshToken : undefined;

  var rsid = (req.cookies.rsid) ? 
  req.cookies.rsid : undefined;

  var sessIat = (req.cookies.sessIat) ? 
  req.cookies.sessIat : undefined;

  var finalTokenObj = {};

  async.waterfall([
    function (callback) {
      redis.getRefreshTokenData(rsid, function (err, redisRefreshTokenData) {
        if(err) {
          const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
      
          return callback({
            message : errMsg,
            httpCode : HTTP_STATUS_CODES.BAD_REQUEST
          });
        }
        
        if(!redisRefreshTokenData || redisRefreshTokenData == null) {
          const errMsg = req.t('INVALID_RT');
      
          return callback({
            message : errMsg,
            httpCode : HTTP_STATUS_CODES.UNAUTHORIZED
          });
        } else if (redisRefreshTokenData.isRevoked || 
          redisRefreshTokenData.isRevoked == true) {

          const errMsg = req.t('TOKEN_ALREADY_USED');
      
          return callback({
            message : errMsg,
            httpCode : HTTP_STATUS_CODES.UNAUTHORIZED
          });
        }

        finalTokenObj.redisRefreshTokenData = redisRefreshTokenData;
        return callback(null);
      });
    }, function (callback) {
      if((!finalTokenObj.redisRefreshTokenData ||
        finalTokenObj.redisRefreshTokenData == null) ||

        (!finalTokenObj.redisRefreshTokenData.accessToken ||
        finalTokenObj.redisRefreshTokenData.accessToken == null) ||

        (!finalTokenObj.redisRefreshTokenData.refreshToken ||
        finalTokenObj.redisRefreshTokenData.refreshToken == null) ||

        (!finalTokenObj.redisRefreshTokenData.iv ||
        finalTokenObj.redisRefreshTokenData.iv == null)) {
          const errMsg = req.t('INVALID_RT');
      
          return callback({
            message : errMsg,
            httpCode : HTTP_STATUS_CODES.UNAUTHORIZED
          });
      } else {
        getRTFromEncryptedToken(
          refreshToken,
          finalTokenObj.redisRefreshTokenData.iv,
          function name(err, decryptedRT) {
            if(err) {
              const errMsg = req.t('INVALID_RT');
          
              return callback({
                message : errMsg,
                httpCode : HTTP_STATUS_CODES.UNAUTHORIZED
              });
            }
  
            return callback(null, decryptedRT);
          }
        );
      }
    }, function (decryptedRT, callback) {
      var decryptedRTObj = JSON.parse(decryptedRT);
      var rtToCheckInDb = (decryptedRTObj.p == 0 || decryptedRTObj.p == '0') ?
        decryptedRTObj.refreshToken : decryptedRTObj.p;
      finalTokenObj.rtToCheckInDb = rtToCheckInDb;

      compareBcryptHash(
        rtToCheckInDb, 
        finalTokenObj.redisRefreshTokenData.refreshToken,
        function name(err, isMatched) {
          if(err) {
            const errMsg = req.t('SOMETHING_WENT_WRONG_PLEASE_TRY_AGAIN');
        
            return callback({
              message : errMsg,
              httpCode : HTTP_STATUS_CODES.BAD_REQUEST
            });
          }

          if(!isMatched) {
            const errMsg = req.t('INVALID_RT');
        
            return callback({
              message : errMsg,
              httpCode : HTTP_STATUS_CODES.UNAUTHORIZED
            });
          }

          finalTokenObj.isRTFound = isMatched;
          return callback(null);
        });
    }, function (callback) {

      // update existing token as revoked
      var newRTData = {
        rsid : rsid,
        isRevoked : true,
        revokedAt : moment().format(config.moment.dbFormat),
        isLoggedOut : true,
        loggedOutAt : moment().format(config.moment.dbFormat)
      }

      redis.updateRefreshTokenData(
        newRTData, function (err, result) {

          if(err) {
            return callback({
              message : err
            });
          }

          return callback(null, finalTokenObj);
        });
    }
  ], function (errObj, finalResultObj) {
      if(errObj) {
        
        return res.status(
          errObj.httpCode
        ).json({
          message : errObj.message
        });
      }

      // return res.status(
      //   HTTP_STATUS_CODES.OK
      // ).json({
      //   message : req.t('LOGOUT_SUCCESSFUL')
      // });

      return res.status(
        HTTP_STATUS_CODES.OK
      ).cookie('accessToken', undefined, {
        httpOnly : true,
        maxAge : 0,
        domain : config.cookieDomain
      }).cookie('refreshToken', undefined, {
        httpOnly : true,
        maxAge : 0,
        domain : config.cookieDomain
      }).cookie('rsid', undefined, {
        httpOnly : true,
        maxAge : 0,
        domain : config.cookieDomain
      }).cookie('sessIat', moment().unix(), {
        httpOnly : true,
        maxAge : 0,
        domain : config.cookieDomain
      }).redirect(config.clientUrl);
  });
}

function generateBcryptHash(str, next) {

  bcrypt.hash(str, 10, function (err, hash) {

    if(err) {

      next(err)
    }
    
    next(null, hash);
  })
}

function compareBcryptHash(str, hash, next) {

  bcrypt.compare(str, hash, function (err, isMatched) {

    if(err) {

      next(err)
    } else {

      next(null, isMatched);
    }
  });
}

function generateRedisRefreshTokenObj(jwtToken, refreshToken, iv, userData, next) {

  generateBcryptHash(refreshToken, function (err, hashedRT) {

    if(err) {
      next(err)
    }

    generateBcryptHash(jwtToken, function (err, hashedJWT) {

      if(err) {
        next(err)
      }
      
      var refreshTokenObj = {
        rsid : cuid(),
        userId : userData.user_id,
        refreshToken : hashedRT,
        accessToken : hashedJWT,
        iv : iv,
        expiresIn : config.refreshToken.expiresIn,
        createdAt : moment().format(config.moment.dbFormat),
        expiresAt : moment().add(
          config.refreshToken.expiresIn, 
          'seconds'
        ).format(
          config.moment.dbFormat
        )
      };
    
      next(null, refreshTokenObj);

    });
  });
}

function getRTFromEncryptedToken(refreshToken, iv, next) {
  var rtArr = refreshToken.split(".");

  try{
    var decryptedCipher = AES256GCM.decrypt(rtArr[0], iv, rtArr[1]);

    next(null, decryptedCipher);
  } catch (e) {

    next(e);
  }
}