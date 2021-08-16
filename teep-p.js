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
const CBORLabels = ['supported-cipher-suites', 'challenge', 'version', 'ocsp-data', 'selected-cipher-suite',
    'selected-version', 'evidence', 'tc-list', 'ext-list', 'manifest-list',
    'msg', 'err-msg', 'evidence-format', 'requested-tc-list', 'unneeded-tc-list',
    'component-id', 'tc-manifest-sequence-number', 'have-binary', 'suit-reports', 'token', 'supported-freshness-mechanisms'];

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

var initMessage = function () { //generate queryRequest
    //make secure token(TBF)
    //record token(TBF)
    //build queryRequest
    var queryRequest = new Object();
    queryRequest.TYPE = TEEP_TYPE_query_request; // TYPE = 1 corresponds to a QueryRequest message sent from the TAM to the TEEP Agent.
    //queryRequest.OPTIONS = null; // Option Field is mandatory? even no elements in options
    queryRequest.OPTIONS = new Map();
    queryRequest.OPTIONS.set(1, [TEEP_AES_CCM_16_64_128_HMAC256__256_X25519_EdDSA]); //cipher-suite as array
    queryRequest.OPTIONS.set(3, [0]); //version
    // @TODO move to buidCborArray func.
    let initToken = new ArrayBuffer(8);
    let initTokenView = new DataView(initToken);
    initTokenView.setUint32(0, 0x77777777); //2004318071
    initTokenView.setUint32(4, 0x77777777);
    queryRequest.OPTIONS.set(20, initToken); // The value in the TOKEN field is used to match requests to responses.
    let buf = new ArrayBuffer(3);
    let dv = new DataView(buf);
    dv.setUint8(0, 01);
    dv.setUint8(1, 02);
    dv.setUint8(2, 05);
    queryRequest.OPTIONS.set(4, buf); //ocsp-data
    //data-item-requested
    queryRequest.REQUEST = 0b0010; // only request is Installed Trusted Apps lists in device
    //supported-freshness-mechanisms
    queryRequest.OPTIONS.set(21, [TEEP_FRESHNESS_NONCE]);

    return queryRequest;
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
        trustedAppUpdate.MANIFEST_LIST = []; // MANIFEST_LIST field is used to convey one or multiple SUIT manifests.
        //trustedAppInstall.MANIFEST_LIST.push("http://" + app.ipAddr + ":8888/TAs/" + trustedAppUUID + ".ta");
        //embedding static SUIT CBOR content
        //let sampleSuitContents = fs.readFileSync('./TAs/suit_manifest_exp1.cbor');
        //trustedAppUpdate.MANIFEST_LIST.push(sampleSuitContents);

        //override URI in SUIT manifest and embed 
        trustedAppUpdate.MANIFEST_LIST.push(setUriDirective("./suit_manifest_expT.cbor", "https://tam-distrubute-point.example.com/"));
        console.log(typeof trustedAppUpdate.MANIFEST_LIST[0]);
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

var buildCborArray = function (obj) {
    //responseObj => cbor-ordered Array
    //common order: 1->type 2->token
    let cborArray = [obj.TYPE];
    switch (obj.TYPE) {
        case TEEP_TYPE_query_request: // QueryRequest
            if (obj.OPTIONS == null) {
                obj.OPTIONS = new cbor.Map();
            }
            cborArray.push(obj.OPTIONS); // option is mandatory field even though no elements.
            cborArray.push(obj.REQUEST); // mandatory

            break;
        case TEEP_TYPE_update: // TrustedAppUpdate
            console.log(obj);
            let TAUpdateOption = new cbor.Map();
            if (obj.hasOwnProperty("MANIFEST_LIST")) { // 10: manifest-list (ref.CBORLabels)
                TAUpdateOption.set(10, obj.MANIFEST_LIST);
            }
            TAUpdateOption.set(20, obj.TOKEN); // 20: token * this token is not neccessary
            if (obj.hasOwnProperty("TC_LIST")) { // 8: tc-list (unneeded and deleting TC-LIST)
                TAUpdateOption.set(8, obj.TC_LIST);
            }
            if (obj.hasOwnProperty("UNNEEDED_TC_LIST")) { // 15: unneeded-tc-list
                TAUpdateOption.set(15, obj.UNNEEDED_TC_LIST);
            }
            cborArray.push(TAUpdateOption);
            break;
        // case 4: // TrustedAppDelete (this type removed and merged into `update`)
        // purged at teep-protocol-05 draft
    }
    return cborArray;
}

var parseCborArrayHelper = function (arr) {
    //request cbor-ordered Array => request Obj
    //common order: 1->type 2->token
    let requestObj = new Object();
    requestObj.TYPE = arr[0];
    //requestObj.TOKEN = arr[1]; Since protocol-05, token is one element of options array.

    //TODO: validate arr elements
    switch (arr[0]) {
        case TEEP_TYPE_query_response: // QueryResponse
            //arr[1] as a Map
            //handle option's Map
            arr[1].forEach(function (val, key, map) {
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
            if (requestObj.hasOwnProperty(CBORLabels[14]) && Array.isArray(requestObj[CBORLabels[14]])) { // unneeded-tc-list Buffer=>String
                requestObj[CBORLabels[14]] = requestObj[CBORLabels[14]].map(function (val) {
                    return val.toString('hex');
                });
                requestObj.UNNEEDED_TC_LIST = requestObj[CBORLabels[14]];
            }
            if (requestObj.hasOwnProperty(CBORLabels[19])) {
                requestObj.TOKEN = requestObj[CBORLabels[19]].toString('hex'); // Buffer => String(hex)
            }
            break;
        case TEEP_TYPE_teep_success: // Success
            if (arr.length == 2) {
                arr[1].forEach(function (val, key, map) {
                    requestObj[CBORLabels[key - 1]] = val;
                });
                // for (key in arr[1]) {
                //      requestObj[CBORLabels[key - 1]] = arr[1][key];
                // }
                if (requestObj.hasOwnProperty(CBORLabels[19])) {
                    requestObj.TOKEN = requestObj[CBORLabels[19]];
                }
                if (requestObj.hasOwnProperty(CBORLabels[18])) {
                    requestObj.reports = requestObj[CBORLabels[18]];
                }
            }
            break;
        case TEEP_TYPE_teep_error: // Error
            arr[1].forEach(function (val, key, map) {
                requestObj[CBORLabels[key - 1]] = val;
            });
            if (requestObj.hasOwnProperty(CBORLabels[19])) {
                requestObj.TOKEN = requestObj[CBORLabels[19]];
            }
            requestObj.ERROR_CODE = arr[2];
            break;
    }
    return requestObj;
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
