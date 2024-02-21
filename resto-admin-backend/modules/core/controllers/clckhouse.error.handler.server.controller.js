var i18next = require("i18next");

var HTTP_STATUS_CODES = require("./httpcodes.server.controller").CODES;
var CUSTOM_ERROR_CODES = require("./customerrorcodes.server.controller").CODES;

exports.handleClickHouseConnErrors = function (connErrOb) {

    // Replace with ClickHouse-specific connection error checks
    if (connErrOb.code == 'CH_ACCESS_DENIED_ERROR') {

        var errMsg = i18next.t("clickhouse:USERNAME_OR_PWD_DENIED");

        return {
            message: errMsg,
            httpStatusCode: HTTP_STATUS_CODES.UNAUTHORIZED,
            customErrCode: CUSTOM_ERROR_CODES.DB_ACCESS_DENIED
        };
    } else if (connErrOb.code == 'CH_CONN_REFUSED') {

        var errMsg = i18next.t("clickhouse:DB_CONNECTION_REFUSED");

        return {
            message: errMsg,
            httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST,
            customErrCode: CUSTOM_ERROR_CODES.DB_CONN_REFUSED
        };
    }

    var errMsg = i18next.t("clickhouse:CONNECTION_ERROR_PLEASE_TRY_AGAIN");

    return {
        message: errMsg,
        httpStatusCode: HTTP_STATUS_CODES.SERVICE_UNAVAILABLE,
        customErrCode: CUSTOM_ERROR_CODES.DB_CONNECTION_ERROR
    };
}

exports.handleClickHouseQueryErrors = function (queryErrOb) {
    
    // Replace with ClickHouse-specific query error checks
    if (queryErrOb.code == 'CH_NO_SUCH_TABLE') {

        var errMsg = i18next.t("clickhouse:TABLE_DOESNOT_EXIST");

        return {
            message: errMsg,
            originalMessage: queryErrOb.sqlMessage,
            httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST,
            customErrCode: CUSTOM_ERROR_CODES.TABLE_DOESNOT_EXIST
        };
    } else if (queryErrOb.code == 'CH_BAD_FIELD_ERROR') {

        var errMsg = i18next.t("clickhouse:TABLE_COLUMN_DOESNOT_EXIST");

        return {
            message: errMsg,
            originalMessage: queryErrOb.sqlMessage,
            httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST,
            customErrCode: CUSTOM_ERROR_CODES.TABLE_COLUMN_DOESNOT_EXIST
        };
    } else if (queryErrOb.code == 'CH_DUP_ENTRY') {

        var errMsg = i18next.t("clickhouse:DUPLICATE_ENTRY");

        return {
            message: errMsg,
            originalMessage: queryErrOb.sqlMessage,
            httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST,
            customErrCode: CUSTOM_ERROR_CODES.RESOURCE_EXISTS
        };
    } else if (queryErrOb.code == 'CH_NO_REFERENCED_ROW') {

        var errMsg = i18next.t("clickhouse:ORIGINAL_RESOURCE_DOES_NOT_EXIST");

        return {
            message: errMsg,
            originalMessage: queryErrOb.sqlMessage,
            httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST,
            customErrCode: CUSTOM_ERROR_CODES.ORIGINAL_RESOURCE_DOES_NOT_EXIST
        };
    } else if (queryErrOb.code == 'CH_BAD_NULL_ERROR') {

        var errMsg = i18next.t("clickhouse:TABLE_COLUMN_CANNOT_BE_NULL");

        return {
            message: errMsg,
            originalMessage: queryErrOb.sqlMessage,
            httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST,
            customErrCode: CUSTOM_ERROR_CODES.TABLE_COLUMN_CANNOT_BE_NULL
        };
    }

    var errMsg = i18next.t("clickhouse:QUERY_ERROR_PLEASE_TRY_AGAIN");

    return {
        message: errMsg,
        httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST,
        customErrCode: CUSTOM_ERROR_CODES.DB_QUERY_ERROR
    };
}
