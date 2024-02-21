exports.removeFieldsFromObj = function(payload = [], fieldsArr = []) {
    // Create a shallow copy of the payload to avoid modifying the original object
    let newPayload = { ...payload };  

    for (let field of fieldsArr) {
        delete newPayload[field];
    }
    
    return newPayload;
}