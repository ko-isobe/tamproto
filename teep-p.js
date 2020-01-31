//var textenc = require('text-encoding');

var init = function () {
    console.log("called TEEP-P init");
    return false;
}

var initMessage = function () {
    //make secure token(TBF)
    //record token(TBF)
    //generate queryRequest
    var queryRequest = new Object();
    queryRequest.TYPE = 1; // TYPE = 1 corresponds to a QueryRequest message sent from the TAM to the TEEP Agent.
    queryRequest.TOKEN = '1'; // The value in the TOKEN field is used to match requests to responses.
    queryRequest.REQUEST = [2]; // request Trusted Apps lists for device

    return queryRequest;
}

var parseQueryResponse = function(obj){
    console.log("*"+ arguments.callee.name);
    //verify token(TBF)
    console.log(obj.TOKEN);
    //record information(TBF)
    console.log(obj.TA_LIST);
    //judge?
    
    //build TA installß message
    let trustedAppInstall = new Object();
    trustedAppInstall.TYPE = 3; // TYPE = 3 corresponds to a TrustedAppInstall message sent from the TAM to the TEEP Agent. 
    trustedAppInstall.TOKEN = '2'; // 
    trustedAppInstall.MANIFEST_LIST = []; // MANIFEST_LIST field is used to convey one or multiple SUIT manifests.
    trustedAppInstall.MANIFEST_LIST[0] = "http://127.0.0.1/TAs/8d82573a-926d-4754-9353-32dc29997f74.ta";
    return trustedAppInstall;
}

var parseSuccessMessage = function(obj){
    console.log("*"+ arguments.callee.name);
    //verify token(TBF)
    console.log(obj.TOKEN);
    //record information(TBF)
    console.log(obj.MSG);

    return;
}

var parse = function(obj){
    console.log("TEEP-Protocol:parse");
    let ret = null;
    //check TEEP Protocol message
    console.log(obj);
    console.log(typeof obj);

    //JSON Scheme validation(TBF)

    switch (obj.TYPE) {
        case 2 : //queryResponse
            ret = parseQueryResponse(obj);
            break;
        case 5 :
            // Success
            parseSuccessMessage(obj);
            return;
            break;
        case 6 :
            // Error
            break;
        default:
            console.log("ERR!: cannot handle this message type :" + obj.TYPE);
            return null;
    }

    return ret;
}

var teepp = new Object();
teepp.init = init;
teepp.initMessage = initMessage;
teepp.parse = parse;
//teepp.queryRequest = queryRequest;

module.exports = teepp;