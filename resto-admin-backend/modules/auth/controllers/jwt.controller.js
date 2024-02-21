'use strict';
const JWT = require('jsonwebtoken');
const config = require('../../../config/config')

exports.generateToken = function (user, next) {
  
  var jwtToken = JWT.sign({
    userId : user.user_id,
    v : 'v1',
    isAdmin: true
  }, 
  config.jwt.secret, { 
    expiresIn: config.jwt.expiresIn
  });

  next(jwtToken);
};
