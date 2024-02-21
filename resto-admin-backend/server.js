const config = require("./config/config");
const express = require("./config/lib/express");
const chalk = require("chalk");

async function startServer() {

  // Initialize Express
  var app = express.init();

  app.listen(config.appPort, function () {
    console.log(
      chalk.green(config.app.title + " is running on port " + config.appPort)
    );
    console.log(config.appDomain + ":" + config.appPort);
  });

  module.exports = app;
}

startServer();
