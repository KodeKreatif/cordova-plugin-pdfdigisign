module.exports = {
    signWithAlias: function (path, alias, name, loc, reason, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "PDFDigiSign", "signWithAlias", [path, alias, name, loc, reason]);
    }
};
