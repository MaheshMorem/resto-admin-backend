var masterConnection = require("../../../config/lib/mysql").masterConn;
var slaveConnection = require("../../../config/lib/mysql").slaveConn;
var HTTP_STATUS_CODES =
  require("../../core/controllers/httpcodes.server.controller").CODES;
var CUSTOM_ERROR_CODES =
require("../../core/controllers/customerrorcodes.server.controller").CODES;
var mysqlErrorHandler = require('../../core/controllers/mysqlerrorhandler.server.controller');
var i18next = require("i18next");
var _ = require("lodash");
var chalk = require("chalk");

exports.registerUser = function (userDataObj, next) {

  masterConnection.getConnection(function (connErr, connection) {

    if (connErr) {
        
      console.error(chalk.red(connErr));

      var finalErrObj = mysqlErrorHandler.handleMysqlConnErrors(connErr);

      if(connection) {
        
        connection.release();
      }

      return next(finalErrObj);
    }

    connection.query(
        "INSERT INTO user SET ?", userDataObj, function (err, rows) {

        if (err) {

          console.error(chalk.red(err));
          connection.release();
          
          var finalErrObj = mysqlErrorHandler.handleMysqlQueryErrors(err);

          return next(finalErrObj);
        }

        connection.release();

        return next(null, rows);
      }
    );
  });
};

exports.registerUserProvider = function (providerDataObj, next) {

  masterConnection.getConnection(function (connErr, connection) {

    if (connErr) {
        
      console.error(chalk.red(connErr));

      var finalErrObj = mysqlErrorHandler.handleMysqlConnErrors(connErr);

      if(connection) {
        
        connection.release();
      }

      return next(finalErrObj);
    }

    connection.query(
        "INSERT INTO user_authentication_provider SET ?", providerDataObj, function (err, rows) {

        if (err) {

          console.error(chalk.red(err));
          connection.release();
          
          var finalErrObj = mysqlErrorHandler.handleMysqlQueryErrors(err);

          return next(finalErrObj);
        }

        connection.release();

        return next(null, rows);
      }
    );
  });
};

exports.registerSecondaryEmail = function (userDataObj, next) {

  masterConnection.getConnection(function (connErr, connection) {

    if (connErr) {
        
      console.error(chalk.red(connErr));

      var finalErrObj = mysqlErrorHandler.handleMysqlConnErrors(connErr);

      if(connection) {
        
        connection.release();
      }

      return next(finalErrObj);
    }

    connection.query(
        "INSERT INTO user_secondary_email SET ?", userDataObj, function (err, rows) {

        if (err) {

          console.error(chalk.red(err));
          connection.release();
          
          var finalErrObj = mysqlErrorHandler.handleMysqlQueryErrors(err);

          return next(finalErrObj);
        }

        connection.release();

        return next(null, rows);
      }
    );
  });
};

exports.getUserEmailAndPwd = function (userEmail, options, next) {
  if (_.isFunction(options) && !next) {
    // set next value as second param
    // sometimes you don't pass options
    next = options;
    options = {
      select: [`*`],
    };
  }

  masterConnection.getConnection(function (connErr, connection) {
    if (connErr) {
      var errMsg = i18next.t("mysql:CONNECTION_ERROR");

      return next({
        message: errMsg,
        httpCode: HTTP_CODES.BAD_REQUEST,
      });
    }

    connection.query(
      `SELECT u.user_id, u.username, u.email, u.password, u.password_salt, u.is_email_verified FROM user as u WHERE u.email = ?`,
      [userEmail],
      function (err, rows) {
        if (err) {
          console.log(err);
          connection.release();

          var errMsg =
            i18next.t("mysql:QUERY_ERR") + " " + i18next.t("PLEASE_TRY_AGAIN");

          return next({
            message: errMsg,
            httpCode: HTTP_CODES.BAD_REQUEST,
          });
        }

        connection.release();

        return next(null, rows);
      }
    );
  });
};


exports.getUserDataByUserId = function (userId, options, next) {

  if (_.isFunction(options) && !next) {

    // set next value as second param
    // sometimes you don't pass options
    next = options;
    options = {
      select: [`*`],
    };
  }

  slaveConnection.getConnection(function (connErr, connection) {

    if (connErr) {
        
      console.error(chalk.red(connErr));

      var finalErrObj = mysqlErrorHandler.handleMysqlConnErrors(connErr);

      if(connection) {
        
        connection.release();
      }

      return next(finalErrObj);
    }

    connection.query(
      `SELECT ${options.select}  FROM user WHERE ?`, [{
        user_id: userId
      }], function (err, rows) {

        if (err) {

          console.error(chalk.red(err));
          connection.release();
          
          var finalErrObj = mysqlErrorHandler.handleMysqlQueryErrors(err);

          return next(finalErrObj);
        }

        connection.release();

        if(rows.length) {

          return next(null, rows[0]);
        } 
        
        return next(null, rows[0]);
      }
    );
  });
};

exports.getAdminUserRoleByUserId = async function(userId, options, next) {
  
  if (_.isFunction(options) && !next) {

    // set next value as second param
    // sometimes you don't pass options
    next = options;
    options = {
      select: [`*`],
    };
  }

  slaveConnection.getConnection(function (connErr, connection) {

    if (connErr) {
        
      console.error(chalk.red(connErr));

      var finalErrObj = mysqlErrorHandler.handleMysqlConnErrors(connErr);

      if(connection) {
        
        connection.release();
      }

      return next(finalErrObj);
    }

    connection.query(
      `SELECT role_id, user_id FROM admin_user_role WHERE user_id = ? AND DELETED_AT IS NULL`, [userId], function (err, rows) {

        if (err) {

          console.error(chalk.red(err));
          connection.release();
          
          var finalErrObj = mysqlErrorHandler.handleMysqlQueryErrors(err);

          return next(finalErrObj);
        }

        connection.release();

        if(rows.length) {

          return next(null, rows[0]);
        } 
        
        return next(null, rows[0]);
      }
    );
  });
};
