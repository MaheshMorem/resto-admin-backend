var masterConnection = require("../../../config/lib/clickhouse").masterConn;
var slaveConnection = require("../../../config/lib/clickhouse").slaveConn;
var clickhouseErrorHandler = require('../../core/controllers/clckhouse.error.handler.server.controller');

var _ = require("lodash");
var chalk = require("chalk");

exports.runQueryInMaster = function(query, data) {
    return new Promise((resolve, reject) => {
        try {
            masterConnection.querying(query, data)
                .then(rows => {
                    resolve(rows);
                })
                .catch(err => {
                    console.error(chalk.red(err));
                    var finalErrObj = clickhouseErrorHandler.handleClickHouseQueryErrors(err);
                    reject(finalErrObj);
                });
        } catch (connErr) {
            console.error(chalk.red(connErr));
            var finalErrObj = clickhouseErrorHandler.handleClickHouseConnErrors(connErr);
            reject(finalErrObj);
        }
    });
};

exports.runQueryInSlave = function(query, data) {
    return new Promise((resolve, reject) => {
        try {
            slaveConnection.querying(query, data)
                .then(rows => {
                    resolve(rows);
                })
                .catch(err => {
                    console.error(chalk.red(err));
                    var finalErrObj = clickhouseErrorHandler.handleClickHouseQueryErrors(err);
                    reject(finalErrObj);
                });
        } catch (connErr) {
            console.error(chalk.red(connErr));
            var finalErrObj = clickhouseErrorHandler.handleClickHouseConnErrors(connErr);
            reject(finalErrObj);
        }
    });
};
