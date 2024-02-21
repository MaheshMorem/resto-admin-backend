var i18next = require("i18next");

var HTTP_STATUS_CODES =
  require("./httpcodes.server.controller").CODES;
var CUSTOM_ERROR_CODES =
require("./customerrorcodes.server.controller").CODES;


exports.handleNeo4jQueryErrors = function (queryErrOb) {

    if(queryErrOb.code == 'ERR_HTTP_INVALID_STATUS_CODE') {

        var errMsg = i18next.t("neo4j:CONNECTION_ERROR");

        return {
            message: errMsg,
            httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST,
            customErrCode: CUSTOM_ERROR_CODES.DB_CONNECTION_ERROR
        };
    }

    var errMsg = i18next.t("neo4j:QUERY_ERROR_PLEASE_TRY_AGAIN");

    return {
        message: errMsg,
        httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST,
        customErrCode: CUSTOM_ERROR_CODES.DB_QUERY_ERROR
    };
}
