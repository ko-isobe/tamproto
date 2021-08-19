/*
* Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
//var textenc = require('text-encoding');
const ip = require('ip');
const app = require('./app');
const cbor = require('cbor');
const fs = require('fs');
const { request } = require('./app');
const trustedAppUUID = "8d82573a-926d-4754-9353-32dc29997f74";

//ref. draft-ietf-teep-protocol-05#appendix-C
const TEEP_TYPE_query_request = 1;
const TEEP_TYPE_query_response = 2;
const TEEP_TYPE_update = 3;
const TEEP_TYPE_teep_success = 5;
const TEEP_TYPE_teep_error = 6;

//ref. draft-ietf-teep-protocol-06#section-5
const CBORLabels = ['supported-cipher-suites', 'challenge', 'versions', 'ocsp-data', 'selected-cipher-suite',
    'selected-version', 'evidence', 'tc-list', 'ext-list', 'manifest-list',
    'msg', 'err-msg', 'evidence-format', 'requested-tc-list', 'unneeded-tc-list',
    'component-id', 'tc-manifest-sequence-number', 'have-binary', 'suit-reports', 'token', 'supported-freshness-mechanisms'];
const cborLtoI = CBORLabels.reduce(function(obj,key,idx){return Object.assign(obj,{[key]:idx+1})},{}); //swap key,value
console.log(cborLtoI);
//ref. draft-ietf-teep-protocol-06#section-7
//cipher-suites
const TEEP_AES_CCM_16_64_128_HMAC256__256_X25519_EdDSA = 1;
const TEEP_AES_CCM_16_64_128_HMAC256__256_P_256_ES256 = 2;

//ref. draft-ietf-teep-protocol-06#apppendix-C
const TEEP_FRESHNESS_NONCE = 0;
const TEEP_FRESHNESS_TIMESTAMP = 1;
const TEEP_FRESHNESS_EPOCH_ID = 2;

var init = function () {
    console.log("called TEEP-P init");
    return false;
}

var initMessage = function () { //generate queryRequest Object
    // see draft-ietf-teep-protocol-06#section-4.4
    var queryRequest = new Object();
    queryRequest.TYPE = TEEP_TYPE_query_request; // TYPE = 1 corresponds to a QueryRequest message sent from the TAM to the TEEP Agent.
    
    queryRequest["supported-cipher-suites"] =[TEEP_AES_CCM_16_64_128_HMAC256__256_X25519_EdDSA]; //cipher-suite as array
    queryRequest["versions"] = [0]; //version as array
    
    let initToken = new ArrayBuffer(8);
    let initTokenView = new DataView(initToken);
    initTokenView.setUint32(0, 0x77777777); //2004318071
    initTokenView.setUint32(4, 0x77777777);
    queryRequest["token"] = initToken; // The value in the TOKEN field is used to match requests to responses.
    
    let buf = new ArrayBuffer(3);
    let dv = new DataView(buf);
    dv.setUint8(0, 01);
    dv.setUint8(1, 02);
    dv.setUint8(2, 05);
    queryRequest["ocsp-data"] = buf; //dummy ocsp-data
    //supported-freshness-mechanisms
    queryRequest["supported-freshness-mechanisms"]  = [TEEP_FRESHNESS_NONCE];
    //data-item-requested
    queryRequest["data-item-requested"] = 0b0010; // only request is Installed Trusted Apps lists in device

    return queryRequest;
}

var parse = function (obj, req) {
    console.log("TEEP-Protocol:parse");
    let ret = null;
    //check TEEP Protocol message
    console.log(obj);
    console.log(typeof obj);

    //Cbor Scheme validation(TBF)

    switch (obj.TYPE) {
        case TEEP_TYPE_query_response: //queryResponse
            ret = parseQueryResponse(obj, req);
            break;
        case TEEP_TYPE_teep_success:
            // Success
            parseSuccessMessage(obj);
            return;
            break;
        case TEEP_TYPE_teep_error:
            // Error
            // parseErrorMessage(obj); @TODO
            // return;
            break;
        default:
            console.log("ERR!: cannot handle this message type :" + obj.TYPE);
            return null;
    }

    return ret;
}

var parseQueryResponse = function (obj, req) {
    console.log("*" + arguments.callee.name);
    //verify token(TBF)
    console.log(obj.TOKEN);
    //record information(TBF)
    console.log(obj.TA_LIST);
    //is delete api? <= !! this is not mentioned in Drafts. <= this will remove due to integrated TAUpdateMessage
    //let deleteFlg = req.path.includes("delete");
    console.log(obj.UNNEEDED_TC_LIST);
    //console.log(deleteFlg);

    //judge?
    let installed = false;
    if (Array.isArray(obj.TA_LIST)) {
        obj.TA_LIST.filter(x => {
            installed = (x === trustedAppUUID);
        });
    }

    let trustedAppUpdate = new Object();
    trustedAppUpdate.TYPE = TEEP_TYPE_update; // TYPE = 3 corresponds to a TrustedAppUpdate message sent from the TAM to the TEEP Agent. 
    //trustedAppUpdate.TOKEN = 2004318072;
    // token is bstr @TODO move to buidCborArray func.
    trustedAppUpdate.TOKEN = new ArrayBuffer(8); //token => bstr .size (8..64)
    let tokenVal = "ABA1A2A3A4A5A6A7"; // hex 
    let tokenView = new DataView(trustedAppUpdate.TOKEN);
    for (let i = 0; i < (tokenVal.length / 8); i++) {
        //console.log(tokenVal.slice(8 * i, 8 * (i + 1)));
        tokenView.setUint32(i * 4, '0x' + tokenVal.slice(8 * i, 8 * (i + 1)));
    }

    // already installed TA?
    if (installed) {
        //build TA delete message
        trustedAppUpdate.TC_LIST = [];
        trustedAppUpdate.TC_LIST[0] = trustedAppUUID;
        //return trustedAppUpdate;
    } else {
        //build TA install message
        trustedAppUpdate["manifest-list"] = []; // MANIFEST_LIST field is used to convey one or multiple SUIT manifests.
        //trustedAppInstall.MANIFEST_LIST.push("http://" + app.ipAddr + ":8888/TAs/" + trustedAppUUID + ".ta");
        //embedding static SUIT CBOR content
        //let sampleSuitContents = fs.readFileSync('./TAs/suit_manifest_exp1.cbor');
        //trustedAppUpdate.MANIFEST_LIST.push(sampleSuitContents);

        //override URI in SUIT manifest and embed 
        trustedAppUpdate["manifest-list"].push(setUriDirective("./TAs/suit_manifest_expX.cbor", "https://tam-distrubute-point.example.com/"));
        console.log(typeof trustedAppUpdate["manifest-list"][0]);
    }

    if (typeof obj.UNNEEDED_TC_LIST !== 'undefined') {
        // unnneeded tc list
        trustedAppUpdate.UNNEEDED_TC_LIST = [];
        let buf = new ArrayBuffer(3);
        let dv = new DataView(buf);
        dv.setUint8(0, 01);
        dv.setUint8(1, 02);
        dv.setUint8(2, 03);
        trustedAppUpdate.UNNEEDED_TC_LIST.push([buf]); // SUIT_Component_Identifier(bstr)
        console.log(typeof trustedAppUpdate.UNNEEDED_TC_LIST[0]);
    }

    return trustedAppUpdate;
}

var parseSuccessMessage = function (obj) {
    console.log("*" + arguments.callee.name);
    //verify token(TBF)
    console.log(obj.TOKEN);
    //record information(TBF)
    console.log(obj.msg);
    if (obj.reports !== undefined) {
        console.log(obj.reports); // teep-protocol-04
    }
    return;
}

var buildCborArray = function (obj) {
    //responseObj => cbor-ordered Array
    //common order: 1->type 2->token
    let cborArray = [obj.TYPE];
    switch (obj.TYPE) {
        case TEEP_TYPE_query_request: // QueryRequest
            let options = new Map(); // option is mandatory field even though no elements.
            CBORLabels.forEach((key,idx)=>{
                if(obj.hasOwnProperty(key)){
                    options.set(idx+1,obj[key]);
                }
            });
            cborArray.push(options); 
            cborArray.push(obj["data-item-requested"]); // mandatory
            console.log(obj);
            console.log(cborArray);
            break;
        case TEEP_TYPE_update: // TrustedAppUpdate
            console.log(obj);
            let TAUpdateOption = new cbor.Map();
            if (obj.hasOwnProperty("manifest-list")) { // 10: manifest-list (ref.CBORLabels)
                TAUpdateOption.set(cborLtoI['manifest-list'], obj["manifest-list"]);
            }
            TAUpdateOption.set(cborLtoI['token'], obj.TOKEN); // 20: token * this token is not neccessary
            if (obj.hasOwnProperty("TC_LIST")) { // 8: tc-list (unneeded and deleting TC-LIST)
                TAUpdateOption.set(cborLtoI['tc-list'], obj.TC_LIST);
            }
            // * $$update-extensions and * $$teep-option-extensions added if needed.
            cborArray.push(TAUpdateOption);
            break;
        default:
            console.log("ERR!: cannot handle this message type in buildCborArray :" + obj.TYPE);
            return null;
    }
    return cborArray;
}

var parseCborArrayHelper = function (arr) {
    //received cbor-ordered Array (in JS Object) => key-value JS Object (to handle familiarly in tamproto)
    // e.g. [1,"ABCDEtoken"] => { "TEEP-TYPE": 1, "TOKEN" : "ABCDEtoken"}
    // call from api.js, not used in teep-p.js
    
    //common order: 1->type 2->token
    let receivedObj = new Object();
    receivedObj.TYPE = arr[0];
    //requestObj.TOKEN = arr[1]; Since protocol-05, token is one element of options array.

    //TODO: validate arr elements
    switch (arr[0]) {
        case TEEP_TYPE_query_response: // QueryResponse
            //arr[1] as a Map
            //handle option's Map
            arr[1].forEach(function (val, key, map) {
                receivedObj[CBORLabels[key - 1]] = val;
            });
            if (receivedObj.hasOwnProperty(CBORLabels[6])) { //eat Buffer=>String
                receivedObj[CBORLabels[6]] = receivedObj[CBORLabels[6]].toString('hex');
            }
            if (receivedObj.hasOwnProperty(CBORLabels[7]) && Array.isArray(receivedObj[CBORLabels[7]])) { // ta-list Buffer=>String
                receivedObj[CBORLabels[7]] = receivedObj[CBORLabels[7]].map(function (val) {
                    return val.toString('hex');
                });
                receivedObj.TA_LIST = receivedObj[CBORLabels[7]];
            }
            if (receivedObj.hasOwnProperty(CBORLabels[14]) && Array.isArray(receivedObj[CBORLabels[14]])) { // unneeded-tc-list Buffer=>String
                receivedObj[CBORLabels[14]] = receivedObj[CBORLabels[14]].map(function (val) {
                    return val.toString('hex');
                });
                receivedObj.UNNEEDED_TC_LIST = receivedObj[CBORLabels[14]];
            }
            if (receivedObj.hasOwnProperty(CBORLabels[19])) {
                receivedObj.TOKEN = receivedObj[CBORLabels[19]].toString('hex'); // Buffer => String(hex)
            }
            break;
        case TEEP_TYPE_teep_success: // Success
            if (arr.length == 2) {
                arr[1].forEach(function (val, key, map) {
                    receivedObj[CBORLabels[key - 1]] = val;
                });
                // for (key in arr[1]) {
                //      requestObj[CBORLabels[key - 1]] = arr[1][key];
                // }
                if (receivedObj.hasOwnProperty(CBORLabels[19])) {
                    receivedObj.TOKEN = receivedObj[CBORLabels[19]];
                }
                if (receivedObj.hasOwnProperty(CBORLabels[18])) {
                    receivedObj.reports = receivedObj[CBORLabels[18]];
                }
            }
            break;
        case TEEP_TYPE_teep_error: // Error
            arr[1].forEach(function (val, key, map) {
                receivedObj[CBORLabels[key - 1]] = val;
            });
            if (receivedObj.hasOwnProperty(CBORLabels[19])) {
                receivedObj.TOKEN = receivedObj[CBORLabels[19]];
            }
            receivedObj.ERROR_CODE = arr[2];
            break;
        default:
            console.log("ERR!: cannot handle this message type in parseCborArrayHelper :" + arr[0]);
            return null;
    }
    return receivedObj;
}

var setUriDirective = function (manifest_path, uri) {
    let suitContents = fs.readFileSync(manifest_path);
    let parsedCbor = cbor.decodeFirstSync(suitContents);

    // suit-install = 9, suit-parameter-uri = 21, suit-directive-override-parameters = 20
    let suit_uri = new cbor.Map();
    suit_uri.set(21, uri);
    parsedCbor.set(9, cbor.encodeOne([20, suit_uri])); // text string (NOT bstr)

    // suit-validate = 10, suit-condition-image-match = 3
    // SUIT_Rep_Policy = uint .bits suit-reporting-bits
    // suit-reporting-bits = &(
    //     suit-send-record-success : 0,
    //     suit-send-record-failure : 1,
    //     suit-send-sysinfo-success : 2,
    //     suit-send-sysinfo-failure : 3
    // )
    parsedCbor.set(10, cbor.encodeOne([3, 15]));

    return cbor.encode(parsedCbor);
}

var teepp = new Object();
teepp.init = init;
teepp.initMessage = initMessage;
teepp.parse = parse;
teepp.buildCborArray = buildCborArray;
teepp.parseCborArray = parseCborArrayHelper;
//teepp.queryRequest = queryRequest;

module.exports = teepp;
