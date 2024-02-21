'use strict';

/**
 * Module dependencies.
 */
var config = require('../config');
var neo4j = require('neo4j-driver');

var neo4jDriver = neo4j.driver(
    'neo4j://' + config.neo4j.master.host,
    neo4j.auth.basic(config.neo4j.master.options.user, config.neo4j.master.options.pass)
)

module.exports.neo4jDriver = neo4jDriver;
