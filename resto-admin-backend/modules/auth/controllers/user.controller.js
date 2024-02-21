'use strict';

var HTTP_STATUS_CODES = require('../../core/controllers/httpcodes.server.controller').CODES;
var UserDbo = require('../dbo/user.dbo');


/**
  * @api {get} /v1/me Get logged in user data
  * @apiGroup User
  *
  * @apiSuccess {String} user_id User id
  * @apiSuccess {String} first_name First name of user
  * @apiSuccess {String} last_name Last name of user
  * @apiSuccess {String} email Email id of user
  * @apiSuccess {String} profile_pic Profile pic of user
  **/

exports.getLoggedInUserData = function (req, res) {

  var userId = req.user.userId;
  var options = {
    select : ['user_id', 'email', 'profile_pic', 'first_name', 'last_name', 'display_name']
  };

  UserDbo.getUserDataByUserId(userId, options, function (err, loggedInUserData) {

    if(err) {

      var responsePayload = {
        message : err.message
      };

      return res.status(
        err.httpStatusCode
      ).json(responsePayload);
    }

    return res.status(
      HTTP_STATUS_CODES.OK
    ).json(loggedInUserData);
});
}
