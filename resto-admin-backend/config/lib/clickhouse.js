'use strict';

/**
 * Module dependencies.
 */
var config = require('../config'),
    ClickHouse = require('clickhouse');

var masterConnConfig = {
    url: config.clickhouse.master.url,
    port: config.clickhouse.master.port,
    user: config.clickhouse.master.options.user,
    password: config.clickhouse.master.options.pass,
    database: config.clickhouse.master.databaseName,
    isUseGzip: false, // optional, can use gzip for data compression
    format: "json", // default format
};

var slaveConnConfig = {
    url: config.clickhouse.slave.url,
    port: config.clickhouse.slave.port,
    user: config.clickhouse.slave.options.user,
    password: config.clickhouse.slave.options.pass,
    database: config.clickhouse.slave.databaseName,
    isUseGzip: false,
    format: "json",
};

var masterConn = new ClickHouse(masterConnConfig);
var slaveConn = new ClickHouse(slaveConnConfig);

module.exports.masterConn = masterConn;
module.exports.slaveConn = slaveConn;
