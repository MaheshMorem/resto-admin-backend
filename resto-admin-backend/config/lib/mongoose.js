'use strict';

/**
 * Module dependencies.
 */
var config = require('../config'),
  chalk = require('chalk'),
  path = require('path'),
  mongoose = require('mongoose');

// Load the mongoose models
module.exports.loadModels = function (callback) {

  // Globbing model files
  config.files.server.models.forEach(function (modelPath) {
    require(path.resolve(modelPath));
  });
};

// Initialize Mongoose
module.exports.connect = function (cb) {
  var dbUri = "mongodb://" + config.mongodb.options.user + ":" +
    config.mongodb.options.pass + "@" + config.mongodb.url + ":" + config.mongodb.port + "/" +
    config.mongodb.databaseName;

  var db = mongoose.connect(dbUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    poolSize: 9,
    socketTimeoutMS: 30000,
    keepAlive: true //,
    // reconnectTries: 30000
  }, function (err) {
    // Log Error
    if (err) {
      console.error(chalk.red('Could not connect to MongoDB!'));
      console.log(err);
    } else {

      // Enabling mongoose debug mode if required
      mongoose.set('debug', config.db.debug);

      // Call callback FN
      if (cb) cb(db);
    }
  });
};

module.exports.disconnect = function (cb) {
  mongoose.disconnect(function (err) {
    console.info(chalk.yellow('Disconnected from MongoDB.'));
    cb(err);
  });
};

mongoose.connection.on('error', function (err) {
  console.info(chalk.yellow('Mongoose conneciton error ', err));
});
