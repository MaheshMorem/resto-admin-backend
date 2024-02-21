var masterConnection = require("../../../config/lib/mysql").masterConn;
var slaveConnection = require("../../../config/lib/mysql").slaveConn;
var mysqlErrorHandler = require('../../core/controllers/mysqlerrorhandler.server.controller');

var _ = require("lodash");
var chalk = require("chalk");

exports.runQueryInMaster = function(query, data) {
    return new Promise((resolve, reject) => {
        masterConnection.getConnection(function(connErr, connection) {
            if (connErr) {
                console.error(chalk.red(connErr));
                var finalErrObj = mysqlErrorHandler.handleMysqlConnErrors(connErr);
                if (connection) {
                    connection.release();
                }
                reject(finalErrObj);
            } else {
                connection.query(query, data, function(err, rows) {
                    connection.release();
                    if (err) {
                        console.error(chalk.red(err));
                        var finalErrObj = mysqlErrorHandler.handleMysqlQueryErrors(err);
                        reject(finalErrObj);
                    } else {
                        resolve(rows);
                    }
                });            
            }
        });
    });
};

exports.runQueryInSlave = function(query, data) {
    return new Promise((resolve, reject) => {
        slaveConnection.getConnection(function(connErr, connection) {
            if (connErr) {
                console.error(chalk.red(connErr));
                var finalErrObj = mysqlErrorHandler.handleMysqlConnErrors(connErr);
                if (connection) {
                    connection.release();
                }
                reject(finalErrObj);
            } else {
                connection.query(query, data, function(err, rows) {
                    connection.release();
                    if (err) {
                        console.error(chalk.red(err));
                        var finalErrObj = mysqlErrorHandler.handleMysqlQueryErrors(err);
                        reject(finalErrObj);
                    } else {
                        resolve(rows);
                    }
                });
            }
        });
    });
};

exports.getConnectionFromMaster = function() {
    return new Promise((resolve, reject) => {
        masterConnection.getConnection(function(connErr, connection) {
            if (connErr) {
                console.error(chalk.red(connErr));
                var finalErrObj = mysqlErrorHandler.handleMysqlConnErrors(connErr);
                if (connection) {
                    connection.release();
                }
                reject(finalErrObj);
            } else {
                resolve(connection);
            }
        });
    });
};

