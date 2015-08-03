module.exports = {
    signWithAlias: function (path, alias, name, loc, reason, imageData, page, x, y, width, height, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "PDFDigiSign", "signWithAlias", [path, alias, name, loc, reason, imageData, page, x, y, width, height]);
    },
    validate: function (path, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "PDFDigiSign", "validate", [path]);
    }
};
