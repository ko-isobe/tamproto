/*
* Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
//var textenc = require('text-encoding');
const ip = require('ip');
const app = require('./app');
const cbor = require('cbor');
const trustedAppUUID = "8d82573a-926d-4754-9353-32dc29997f74";

//ref. draft-ietf-teep-protocol-02#section-5
const CBORLabels = ['cipher-suites', 'nonce', 'version', 'ocsp-data', 'selected-cipher-suite', 'selected-version', 'eat', 'ta-list', 'ext-list', 'manifest-list', 'msg', 'err-msg'];

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
    queryRequest.TOKEN = 12345; // The value in the TOKEN field is used to match requests to responses.
    queryRequest.REQUEST = 0b0010; // only request is Installed Trusted Apps lists in device

    return queryRequest;
}

var parseQueryResponse = function (obj, req) {
    console.log("*" + arguments.callee.name);
    //verify token(TBF)
    console.log(obj.TOKEN);
    //record information(TBF)
    console.log(obj.TA_LIST);
    //is delete api? <= !! this is not mentioned in Drafts.
    let deleteFlg = req.path.includes("delete");
    //console.log(deleteFlg);

    //judge?
    let installed = false;
    if (Array.isArray(obj.TA_LIST)) {
        obj.TA_LIST.filter(x => {
            installed = (x === trustedAppUUID);
        });
    }

    if (deleteFlg) {
        // already installed TA?
        if (installed) {
            //build TA delete message
            let trustedAppDelete = new Object();
            trustedAppDelete.TYPE = 4; // TYPE = 4 corresponds to a TrustedAppDelete message sent from the TAM to the TEEP Agent. 
            trustedAppDelete.TOKEN = '2';
            trustedAppDelete.TA_LIST = [];
            trustedAppDelete.TA_LIST[0] = trustedAppUUID;
            return trustedAppDelete;
        } else {
            //nothing to do
            return null;
        }
    } else {
        // already installed TA?
        if (installed) {
            //nothing to do
            return null;
        } else {
            //build TA install message
            let trustedAppInstall = new Object();
            trustedAppInstall.TYPE = 3; // TYPE = 3 corresponds to a TrustedAppInstall message sent from the TAM to the TEEP Agent. 
            trustedAppInstall.TOKEN = 23456; // 
            trustedAppInstall.MANIFEST_LIST = []; // MANIFEST_LIST field is used to convey one or multiple SUIT manifests.
            trustedAppInstall.MANIFEST_LIST[0] = "http://" + app.ipAddr + ":8888/TAs/" + trustedAppUUID + ".ta";
            return trustedAppInstall;
        }
    }
}

var parseSuccessMessage = function (obj) {
    console.log("*" + arguments.callee.name);
    //verify token(TBF)
    console.log(obj.TOKEN);
    //record information(TBF)
    console.log(obj.msg);

    return;
}

var parse = function (obj, req) {
    console.log("TEEP-Protocol:parse");
    let ret = null;
    //check TEEP Protocol message
    console.log(obj);
    console.log(typeof obj);

    //JSON Scheme validation(TBF)

    switch (obj.TYPE) {
        case 2: //queryResponse
            ret = parseQueryResponse(obj, req);
            break;
        case 5:
            // Success
            parseSuccessMessage(obj);
            return;
            break;
        case 6:
            // Error
            break;
        default:
            console.log("ERR!: cannot handle this message type :" + obj.TYPE);
            return null;
    }

    return ret;
}

var buildCborArray = function (obj) {
    //responseObj => cbor-ordered Array
    //common order: 1->type 2->token
    let cborArray = [obj.TYPE, obj.TOKEN];
    switch (obj.TYPE) {
        case 1: // QueryRequest
            if (obj.hasOwnProperty('OPTIONS')) { // Option is Option*
                cborArray.push(obj.Options);
            }
            cborArray.push(obj.REQUEST); // mandatory
            break;
        case 3: // TrustedAppInstall
            let TAInstallOption = new cbor.Map();
            TAInstallOption.set(10, obj.MANIFEST_LIST); // 10: manifest-list (ref.CBORLabels)
            cborArray.push(TAInstallOption);
            break;
        case 4: // TrustedAppDelete
            break;
    }
    return cborArray;
}

var parseCborArrayHelper = function (arr) {
    //request cbor-ordered Array => request Obj
    //common order: 1->type 2->token
    let requestObj = new Object();
    requestObj.TYPE = arr[0];
    requestObj.TOKEN = arr[1];

    //TODO: validate arr elements
    switch (arr[0]) {
        case 2: // QueryResponse
            //arr[2] as a Map
            //handle option's Map
            arr[2].forEach(function (val, key, map) {
                requestObj[CBORLabels[key - 1]] = val;
            });
            if (requestObj.hasOwnProperty(CBORLabels[6])) { //eat Buffer=>String
                requestObj[CBORLabels[6]] = requestObj[CBORLabels[6]].toString('hex');
            }
            if (requestObj.hasOwnProperty(CBORLabels[7]) && Array.isArray(requestObj[CBORLabels[7]])) { // ta-list Buffer=>String
                requestObj[CBORLabels[7]] = requestObj[CBORLabels[7]].map(function (val) {
                    return val.toString('hex');
                });
                requestObj.TA_LIST = requestObj[CBORLabels[7]];
            }
            break;
        case 5: // Success
            if (arr.length == 3) {
                arr[2].forEach(function (val, key, map) {
                    requestObj[CBORLabels[key - 1]] = val;
                });
            }
            break;
        case 6: // Error
            requestObj.ERROR_CODE = arr[2];
            break;
    }
    return requestObj;
}
var teepp = new Object();
teepp.init = init;
teepp.initMessage = initMessage;
teepp.parse = parse;
teepp.buildCborArray = buildCborArray;
teepp.parseCborArray = parseCborArrayHelper;
//teepp.queryRequest = queryRequest;

module.exports = teepp;
