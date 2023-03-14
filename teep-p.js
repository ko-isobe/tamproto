/*
* Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
//var textenc = require('text-encoding');
const ip = require('ip');
//const app = require('./app');
const cbor = require('cbor');
const fs = require('fs');
//const { request } = require('./app');
const yaml = require('js-yaml');
const tokenManager = require('./tokenmanager');
const log4js = require('log4js');
const logger = log4js.getLogger('teep-p.js');
logger.level = 'debug';

const trustedAppUUID = "8d82573a-926d-4754-9353-32dc29997f74";
let rules;
// loading update rules definition
try {
    rules = yaml.load(fs.readFileSync('./rules.yaml', 'utf8'));
    logger.debug(rules);
} catch (e) {
    logger.error('Failed to load rules.yaml :' + e);
    return;
}

//ref. draft-ietf-teep-protocol-05#appendix-C
const TEEP_TYPE_query_request = 1;
const TEEP_TYPE_query_response = 2;
const TEEP_TYPE_update = 3;
const TEEP_TYPE_teep_success = 5;
const TEEP_TYPE_teep_error = 6;

//ref. draft-ietf-teep-protocol-08#section-6 , ocsp-data is obsoleted.
const CBORLabels = ['supported-cipher-suites', 'challenge', 'versions', null, 'selected-cipher-suite',
    'selected-version', 'evidence', 'tc-list', 'ext-list', 'manifest-list',
    'msg', 'err-msg', 'evidence-format', 'requested-tc-list', 'unneeded-tc-list',
    'component-id', 'tc-manifest-sequence-number', 'have-binary', 'suit-reports', 'token', 'supported-freshness-mechanisms'];
const cborLtoI = CBORLabels.reduce(function (obj, key, idx) { return Object.assign(obj, { [key]: idx + 1 }) }, {}); //swap key,value
//logger.debug('TEEP Const Values array set as:', cborLtoI);

//ref. algorithm identifiers defined in the IANA COSE Algorithms Registry
const COSE_alg_es256 = -7;
const COSE_alg_eddsa = -8;
const COSE_alg_ps256 = -37;
const COSE_alg_ps384 = -38;
const COSE_alg_ps512 = -39;
const COSE_alg_rsa_oaep_256 = -41;
const COSE_alg_rsa_oaep_512 = -42;
const COSE_alg_accm_16_64_128 = 10;
const COSE_alg_hmac_256 = 5;

//ref. draft-ietf-teep-protocol-10#section-8
//cipher-suite
const COSE_Sign1_Tagged = 18;
const TEEP_operation_sign1_eddsa = [COSE_Sign1_Tagged, COSE_alg_eddsa];
const TEEP_operation_sign1_es256 = [COSE_Sign1_Tagged, COSE_alg_es256];

const TEEP_cipher_suite_sign1_eddsa = [TEEP_operation_sign1_eddsa];
const TEEP_cipher_suite_sign1_es256 = [TEEP_operation_sign1_es256];

//ref. draft-ietf-teep-protocol-06#apppendix-C
const TEEP_FRESHNESS_NONCE = 0;
const TEEP_FRESHNESS_TIMESTAMP = 1;
const TEEP_FRESHNESS_EPOCH_ID = 2;

//ref. draft-ietf-teep-protocol-08#section-4.6
const TEEP_ERR_PERMANENT_ERROR = 1;
const TEEP_ERR_UNSUPPORTED_EXTENSION = 2;
const TEEP_ERR_UNSUPPORTED_FRESHNESS_MECHANISMS = 3;
const TEEP_ERR_UNSUPPORTED_MSG_VERSION = 4;
const TEEP_ERR_UNSUPPORTED_CIPHER_SUITES = 5;
const TEEP_ERR_BAD_CERTIFICATE = 6;
const TEEP_ERR_CERTIFICATE_EXPIRED = 9;
const TEEP_ERR_TEMPORARY_ERROR = 10;
const TEEP_ERR_MANIFEST_PROCESSING_FAILED = 17;

var init = function () {
    logger.info("called TEEP-P init");
    return false;
}

var initMessage = async function () { //generate queryRequest Object
    // see draft-ietf-teep-protocol-06#section-4.4
    var queryRequest = new Object();
    queryRequest.TYPE = TEEP_TYPE_query_request; // TYPE = 1 corresponds to a QueryRequest message sent from the TAM to the TEEP Agent.

    queryRequest["versions"] = [0]; //version as array

    let initToken = new ArrayBuffer(8);
    // let initTokenView = new DataView(initToken);
    // initTokenView.setUint32(0, 0x77777777); //2004318071
    // initTokenView.setUint32(4, 0x77777777);
    initToken = await tokenManager.generateToken();
    queryRequest["token"] = initToken; // The value in the TOKEN field is used to match requests to responses.

    //supported-freshness-mechanisms
    queryRequest["supported-freshness-mechanisms"] = [TEEP_FRESHNESS_NONCE];
    //supported-cipher-suites
    queryRequest["supported-cipher-suites"] = [TEEP_cipher_suite_sign1_es256];
    //data-item-requested
    queryRequest["data-item-requested"] = 0b0010; // only request is Installed Trusted Apps lists in device

    console.log(queryRequest);
    return queryRequest;
}

var parse = async function (obj, req) {
    logger.info("TEEP-Protocol:parse");
    let ret = null;
    //check TEEP Protocol message
    logger.debug(obj);
    logger.debug(typeof obj);

    //Cbor Scheme validation(TBF)

    switch (obj.TYPE) {
        case TEEP_TYPE_query_response: //queryResponse
            ret = await parseQueryResponse(obj, req);
            break;
        case TEEP_TYPE_teep_success:
            // Success
            await parseSuccessMessage(obj);
            return;
            break;
        case TEEP_TYPE_teep_error:
            // Error
            await parseErrorMessage(obj);
            return;
            break;
        default:
            logger.error("ERR!: cannot handle this message type :" + obj.TYPE);
            return null;
    }

    return ret;
}

var parseQueryResponse = async function (obj, req) {
    logger.info("*" + arguments.callee.name);
    // selected version
    if (typeof obj.SELECTED_VERSION !== 'undefined') {
        logger.info("Selected Version is " + obj.SELECTED_VERSION);
        // check the version
    }

    //verify token
    logger.debug(obj.TOKEN);
    let isValidToken = await tokenManager.consumeToken(obj.TOKEN);
    if (!isValidToken) {
        logger.error("Claimed token is not valid.")
    }

    logger.debug(obj.TA_LIST);
    logger.debug(obj.UNNEEDED_TC_LIST);
    //console.log(deleteFlg);

    // let installed = false;
    // if (Array.isArray(obj.TA_LIST)) {
    //     obj.TA_LIST.filter(x => {
    //         installed = (x === trustedAppUUID);
    //     });
    // }

    // ciphersuite
    if (typeof obj.SELECTED_CIPHER_SUITE !== 'undefined') {
        logger.info("Selected Cipher Suite is " + obj.SELECTED_CIPHER_SUITE);
        // check whether the claimed suite is available in TAM
        // set the algorithm and key according to the claimed suite
    }

    // attestation
    if (typeof obj.EVIDENCE_FORMAT !== 'undefined') {
        logger.info("Evidence format is " + obj.EVIDENCE_FORMAT);
    }
    if (typeof obj.EVIDENCE !== 'undefined') {
        logger.info("QueryResponse contains Evidence.");
    }

    // building the response
    let trustedAppUpdate = new Object();
    trustedAppUpdate.TYPE = TEEP_TYPE_update; // TYPE = 3 corresponds to a TrustedAppUpdate message sent from the TAM to the TEEP Agent. 
    trustedAppUpdate.TOKEN = await tokenManager.generateToken();

    // choosing install/remove TA along with rules.json
    let deviceId = "teep-agent"; // set by attestation result
    console.log(rules);
    let rule = null;
    if (deviceId in rules) {
        rule = rules[deviceId];
    } else {
        logger.error("cannot find device rule in config.json");
    }
    console.log(rule.rules);

    // retrieve the responsed condition
    logger.debug(obj.TA_LIST);
    // obj.TA_LIST.forEach(x => x.forEach((val,key)=>console.log(val + " from " + key)));
    let cond_arr = [];
    obj.TA_LIST.map(x => {
        // x is Map (component-id => [* SUIT_Component_Identifier])
        // SUIT_Component_Identifier is bstr array
        let SUIT_idenfiers = x.get(16);
        let arr = [];
        SUIT_idenfiers.forEach(y => arr.push(Buffer.from(y)));
        cond_arr.push(arr);
    });
    logger.debug(cond_arr);

    // translate rule's list to Buffer array
    let tmp_rules = [];
    let tmp_updates = []; // update field's array
    rule.rules.forEach(x => {
        if (x.installed !== null) {
            let arr = x.installed.map(y => {
                return y.map(z => Buffer.from(z, 'hex'));
            });
            tmp_rules.push(arr);
            tmp_updates.push(x.update);
        }
    });
    logger.debug(tmp_rules);
    logger.debug(tmp_updates);

    // seek the matched rule
    let update_rule = null;
    let i = 0;
    update_rule = tmp_rules.find((x, index) => {
        console.log(x); console.log(cond_arr); console.log(JSON.stringify(x) == JSON.stringify(cond_arr));
        if (JSON.stringify(x) == JSON.stringify(cond_arr)) {
            i = index;
            return true;
        }
    });
    logger.debug(update_rule);
    logger.debug(tmp_updates[i]);

    if (update_rule !== null) {
        trustedAppUpdate["manifest-list"] = [];
        // embed the SUIT manifests
        for (const target of tmp_updates[i]) {
            let suitContents = fs.readFileSync('./TAs/' + target);
            trustedAppUpdate["manifest-list"].push(suitContents);
        }
    }

    return trustedAppUpdate;
}

var parseSuccessMessage = async function (obj) {
    logger.info("*" + arguments.callee.name);
    //verify token(TBF)
    logger.debug(obj.TOKEN);
    let isValidToken = await tokenManager.consumeToken(obj.TOKEN);
    if (!isValidToken) {
        logger.error("ERR! Claimed token is not valid.")
    }
    logger.debug(obj.msg);
    if (typeof obj.reports !== 'undefined') {
        logger.debug(obj.reports); // teep-protocol-04
    }
    return;
}

var parseErrorMessage = async function (obj) {
    logger.info("*" + arguments.callee.name);
    //verify token(TBF)
    logger.debug(obj.TOKEN);
    let isValidToken = await tokenManager.consumeToken(obj.TOKEN);
    if (!isValidToken) {
        logger.error("Claimed token is not valid.")
    }
    logger.debug(obj.ERR_MSG);
    if (typeof obj.reports !== 'undefined') {
        logger.debug(obj.reports); // teep-protocol-04
    }
    // supported ciphersuites
    if (typeof obj.SUPPORTED_CIPHER_SUITES !== 'undefined') {
        logger.info("Supported Cipher Suites are " + obj.SUPPORTED_CIPHER_SUITES);
        // check whether the claimed suites are available in TAM
    }

    // supported freshness mechanisms
    if (typeof obj.SUPPORTED_FRESHNESS_MECHANISMS !== 'undefined') {
        logger.info("Supported Cipher Suites are " + obj.SUPPORTED_FRESHNESS_MECHANISMS);
        // check whether the claimed mechanisms are available in TAM
    }

    // supported version
    if (typeof obj.VERSIONS !== 'undefined') {
        logger.info("Supported Versions are " + obj.VERSIONS);
    }

    return;
}

var buildCborArray = function (obj) {
    //responseObj => cbor-ordered Array
    //common order: 1->type 2->options
    let cborArray = [obj.TYPE];
    switch (obj.TYPE) {
        case TEEP_TYPE_query_request: // QueryRequest
            let options = new Map(); // option is mandatory field even though no elements.
            CBORLabels.forEach((key, idx) => {
                if (obj.hasOwnProperty(key) && key !== "supported-cipher-suites") { //supported-cipher-suites isn't include in options
                    options.set(idx + 1, obj[key]);
                }
            });
            cborArray.push(options);
            cborArray.push(obj["supported-cipher-suites"]); // mandatory
            cborArray.push(obj["data-item-requested"]); // mandatory
            logger.debug(obj);
            logger.debug(cborArray);
            break;
        case TEEP_TYPE_update: // TrustedAppUpdate
            logger.debug(obj);
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
            logger.error("cannot handle this message type in buildCborArray :" + obj.TYPE);
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
                // receivedObj[CBORLabels[7]] = receivedObj[CBORLabels[7]].map(function (val) {
                //     return val.toString('hex');
                // });
                // receivedObj.TA_LIST = receivedObj[CBORLabels[7]];
                receivedObj.TA_LIST = receivedObj[CBORLabels[7]];
                logger.debug(receivedObj.TA_LIST);
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
            if (receivedObj.hasOwnProperty(CBORLabels[12])) {
                receivedObj.EVIDENCE_FORMAT = receivedObj[CBORLabels[12]]; //text
            }
            if (receivedObj.hasOwnProperty(CBORLabels[6])) {
                receivedObj.EVIDENCE = receivedObj[CBORLabels[6]]; // bstr
            }
            if (receivedObj.hasOwnProperty(CBORLabels[4])) {
                receivedObj.SELECTED_CIPHER_SUITE = receivedObj[CBORLabels[4]]; //array
            }
            if (receivedObj.hasOwnProperty(CBORLabels[5])) {
                receivedObj.SELECTED_VERSION = receivedObj[CBORLabels[5]]; // array
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
            if (receivedObj.hasOwnProperty(CBORLabels[0])) {
                receivedObj.SUPPORTED_CIPHER_SUITES = receivedObj[CBORLabels[0]]; //array
            }
            if (receivedObj.hasOwnProperty(CBORLabels[20])) {
                receivedObj.SUPPORTED_FRESHNESS_MECHANISMS = receivedObj[CBORLabels[20]]; //array
            }
            if (receivedObj.hasOwnProperty(CBORLabels[2])) {
                receivedObj.VERSIONS = receivedObj[CBORLabels[2]]; //array
            }
            if (receivedObj.hasOwnProperty(CBORLabels[18])) {
                receivedObj.SUIT_REPORTS = receivedObj[CBORLabels[18]]; //array
            }
            break;
        default:
            logger.error("cannot handle this message type in parseCborArrayHelper :" + arr[0]);
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
