const crypto = require('crypto');
var config = require("../../../config/config");
const i18next = require('i18next');
var HTTP_STATUS_CODES = require("../../core/controllers/httpcodes.server.controller").CODES;
var CUSTOM_ERROR_CODES = require('../../core/controllers/customerrorcodes.server.controller').CODES;


// AES-256-CBC uses a 256 bit key and an IV (Initialization Vector) of 128 bits
const ENCRYPTION_KEY = config.encrytpion.key;
const IV_LENGTH = 16;

function encrypt(text) {

    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    try{
        let textParts = text.split(':');
        let iv = Buffer.from(textParts.shift(), 'hex');
        let encryptedText = Buffer.from(textParts.join(':'), 'hex');
        let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString();
    } catch(err) {

        if(err && err.code && err.code == 'ERR_CRYPTO_INVALID_IV') {
            throw {
                message: i18next.t("common:UNEXPECTED_ERROR"),
                customErrCode: CUSTOM_ERROR_CODES.DECRYPTION_IV_ERROR,
                httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST
            };
        } else {
            throw {
                message: i18next.t("common:UNEXPECTED_ERROR"),
                customErrCode: CUSTOM_ERROR_CODES.DECRYPTION_IV_ERROR,
                httpStatusCode: HTTP_STATUS_CODES.BAD_REQUEST
            };
        }
    }
}

module.exports = { encrypt, decrypt };
