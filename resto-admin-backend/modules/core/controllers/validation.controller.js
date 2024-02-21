var _ = require('lodash');

module.exports.validate = function (schema, payload) {

  var response = {};
  var errorMessages = [];
  const payloadValidation = schema.validate(payload, {
    stripUnknown : true,
    abortEarly : false
  });

  // if(payloadValidation.error && payloadValidation.error.details) {

  //   _.map(payloadValidation.error.details, function (item) {
      
  //     errorMessages.push(item);
  //   });
  // }

  if(payloadValidation.error && payloadValidation.error.details) {

    response.error = payloadValidation.error.details;
  }

  response.value = payloadValidation.value;

  return response;
}