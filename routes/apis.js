/*
* Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
var express = require('express');
var router = express.Router();
//var jws = require('jws');
var teepP = require("../teep-p");
var jose = require('node-jose');
var cbor = require('cbor');
var cose = require('cose-js');
var fs = require('fs');
require('express-async-errors');
var keyManager = require('../keymanager.js');
const log4js = require('log4js');
const logger = log4js.getLogger('apis.js');
logger.level = 'debug';

const checkContentType = (req, res, next) => {
   if (req.headers['content-type'] !== "application/teep+cbor") {
      logger.warn("apis.js: Inappropirate content-type request");
      logger.debug(req.headers['content-type']);
      res.set(null);
      res.status(415).send('no content');
      res.end();
      return;
   }
   next();
};

router.get('/', function (req, res, next) {
   var param = { "key": "This is sample" };
   res.header('Content-Type', 'application/json; charset=utf-8');
   res.send(param);
});

let teepImplHandler = async function (req, body, kid = null) {
   // See teep-protocol-06#Section 6.1
   // Pass the request to teep-p.js and get the reseponse.
   let ret = null;
   if (req.headers['content-length'] == 0) {
      //body is empty
      logger.info("TAM API launch");
      //Call ProcessConnect API
      ret = await teepP.initMessage();
      return ret;
   } else {
      logger.info("TAM ProcessTeepMessage instance");
      //Call ProcessTeepMessage API
      ret = await teepP.parse(body, req, kid);
      logger.info("TAM ProcessTeepMessage response");
      //logger.debug(ret);
      if (ret == null) {
         //invalid message from client device
         logger.warn("WARNING: Agent may sent invalid contents. TAM responses null."); // @TODO review this message
      }
      return ret;
   }
}

// no encrypt (currently unused API)
router.post('/tam', function (req, res, next) {
   // // check POST content
   // console.log("Access from: " + req.ip);
   // console.log(req.headers);
   // console.log(req.body);
   // let ret = null;

   // //set response header
   // res.set({
   //    'Content-Type': 'application/teep+json',
   //    'X-Content-Type-Options': 'nosniff',
   //    'Content-Security-Policy': "default-src 'none'",
   //    'Referrer-Policy': 'no-referrer'
   // });

   // ret = teepImplHandler(req, req.body);

   // if (ret == null) {
   //    res.set(null);
   //    res.status(204);
   //    res.end();
   // } else {
   //    //res.set(ret);
   //    res.send(JSON.stringify(ret));
   //    res.end();
   // }

   // return;
});

//CBOR (no encrypt and sign)
router.post('/tam_cbor', checkContentType, async function (req, res, next) {
   // check POST content
   logger.info("Access to tam_cbor API from: " + req.ip);
   logger.debug(req.headers);
   logger.debug(req.body);
   let ret = null;
   let parsedCbor = null;

   //set response header
   res.set({
      'Content-Type': 'application/teep+cbor',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'",
      'Referrer-Policy': 'no-referrer'
   });

   if (req.headers['content-length'] != 0) { // any content is received
      try {
         parsedCbor = cbor.decodeFirstSync(req.body); // cbor=> JS Object
      } catch (e) {
         logger.error("Cbor parse error:" + e);
         res.status(400);
         res.end();
         return;
      }
      logger.debug(teepP.parseCborArray(parsedCbor));
      ret = await teepImplHandler(req, teepP.parseCborArray(parsedCbor));
   } else {
      //Initialize TEEP-P
      ret = await teepImplHandler(req, req.body);
   }

   if (ret == null) { // TAM can't handle Agent's message.
      res.set(null);
      res.status(204);
      res.end();
      logger.debug("Response from TAM / Content-length:", res.get('content-length'), "statusCode: ", res.statusCode);
   } else { // TAM sends valid response to Agent.
      //console.log(ret);
      let cborResponseArray = teepP.buildCborArray(ret);
      //console.log(cborResponseArray);
      res.send(cbor.encode(cborResponseArray));
      logger.debug("Response from TAM / Content-length:", res.get('content-length'), "statusCode: ", res.statusCode);
      res.end();
   }

   return;
});

//COSE (with sign)　@TODO
router.post('/tam_cose', async function (req, res, next) {
   // check POST content
   logger.info("Access to tam_cose API from: " + req.ip);
   logger.debug(req.headers);
   logger.debug(req.body);
   let ret = null;
   let parsedCbor = null;

   //set response header
   res.set({
      'Content-Type': 'application/teep+cose',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'",
      'Referrer-Policy': 'no-referrer'
   });

   //retrieve TAM private key
   let TamKeyObj = JSON.parse(keyManager.getKeyBinary("TAM_priv").toString());
   let TeePubKeyObj = JSON.parse(keyManager.getKeyBinary("TEE_pub").toString()); //use default Agent key

   if (req.headers['content-length'] != 0) { // request body is not null. Verify the TEEP Agent's signature
      //verify the cose
      try {
         //check COSE_Sign1 Tag and choose Agent Public Key from COSE unprotected header's kid
         let cose_object = cbor.decodeFirstSync(req.body);
         if (cose_object.tag !== 18) { // is COSE_Sign1?
            logger.debug(cose_object);
            throw new Error("Received object isn't COSE_Sign1. tag is " + cose_object.tag);
         }
         let kid = null;
         if (cose_object.value[1] instanceof Map) {
            if (cose_object.value[1].has(4) && keyManager.isStoredAgentKey(Buffer.from(cose_object.value[1].get(4)).toString())) { // unprotected header has kid(4)
               kid = Buffer.from(cose_object.value[1].get(4)).toString();
               TeePubKeyObj = JSON.parse(keyManager.getAgentKeyBinary(kid)); // use obtained kid's Public key
               logger.info("Use the Agent Public key (kid=" + kid + ")");
            } else {
               logger.warn("Received COSE doesn't have TAM-known kid in unprotected header.");
            }
         } else {
            logger.info("Use default Agent Public key.");
         }
         // verify
         // key loading 
         let verifyKey = {
            'key': {
               'x': Buffer.from(TeePubKeyObj.x, 'base64'),
               'y': Buffer.from(TeePubKeyObj.y, 'base64')
            }
         };
         let cbor_payload = await cose.sign.verify(req.body, verifyKey);
         parsedCbor = cbor.decodeFirstSync(cbor_payload);
         logger.debug(parsedCbor);
         ret = await teepImplHandler(req, teepP.parseCborArray(parsedCbor), kid);
      } catch (e) {
         logger.error("COSE parse error:" + e);
         res.status(400);
         res.end();
         return;
      }
   } else { // request body is null. Needless to verify the request
      //Initialize TEEP-P
      ret = await teepImplHandler(req, req.body);
   }

   //sign the response 
   if (ret == null) {
      res.set(null);
      res.status(204);
      res.end();
   } else {
      //console.log(ret);
      let cborResponseArray = teepP.buildCborArray(ret);
      logger.debug(cborResponseArray);
      //logger.debug(TamKeyObj);
      let plainPayload = await cbor.encodeAsync(cborResponseArray);
      let headers = {
         'p': { 'alg': 'ES256' },
         'u': { 'kid': '' }
      };
      if (TamKeyObj.hasOwnProperty('crv')) {
         if (TamKeyObj.crv === 'P-256') {
            headers.p = { 'alg': 'ES256' };
         } else if (TamKeyObj.crv === 'Ed25519') {
            headers.p = { 'alg': 'EdDSA' };
         }
      }
      if (TamKeyObj.hasOwnProperty('kid')) { // if TAM_priv has kid, set the same kid in COSE header
         headers.u = { 'kid': TamKeyObj.kid };
      }
      let signer = {
         'key': {
            'd': Buffer.from(TamKeyObj.d, 'base64')
         }
      };
      let cosePayload = await cose.sign.create(headers, plainPayload, signer);
      res.send(cosePayload);
      res.end();
   }
   logger.debug("Response from TAM / Content-length:", res.get('content-length'), "statusCode: ", res.statusCode);
   return;
});

//COSE Sign verify test
//This is a utilllity API. not defined in TEEP specs.
router.post('/cose_verify', async function (req, res, next) {
   // check POST content
   logger.info("Access to cose_verify API from: " + req.ip);
   logger.debug(req.headers);
   logger.debug(req.body);
   let ret = null;

   //retrieve TEE public key
   let TeeKeyObj = JSON.parse(keyManager.getKeyBinary("TEE_pub").toString());

   //let promise = new Promise((resolve, reject) => {
   try {
      // verify
      // key loading          //const p = keyReload();
      let verifyKey = {
         'key': {
            'x': Buffer.from(TeeKeyObj.x, 'base64'),
            'y': Buffer.from(TeeKeyObj.y, 'base64')
         }
      };
      // await cose.sign.verify(req.body, verifyKey).then((buf) => {
      //    console.log(buf.toString('utf8'));
      //    parsedCbor = cbor.decodeFirstSync(buf);
      //    console.log(parsedCbor);
      //    res.status(200);
      //    res.end();
      //    resolve(parsedCbor);
      // });
      const buf = await cose.sign.verify(req.body, verifyKey);
      logger.info('Verified message: ' + buf.toString('utf8'));
      //resolve(buf);
      //console.log(x);
      res.send(buf);
      res.end();
   } catch (e) {
      logger.debug("Cbor parse error:" + e);
      res.status(400);
      //reject(e);
      return;
   }
   // });
   // promise.then(function (x) {
   // console.log(x);
   // res.send(x);
   // res.end();
   return;
   //});

});

let signAndEncrypt = function (data) {
   const p = new Promise((resolve, reject) => {
      // @TODO switch using keyManager
      jose.JWS.createSign({ format: "flattened" }, jwk_tee_privkey).update(JSON.stringify(data)).final().then(
         function (result) {
            logger.debug(result);
            logger.debug(typeof result);
            //signedRequest = result;
            // @TODO switch using keyManager
            jose.JWE.createEncrypt({ format: "flattened", fields: { alg: 'RSA1_5' } }, jwk_tam_privkey)
               .update(JSON.stringify(result))
               .final().then(
                  async function (ret) {
                     logger.debug(ret);
                     val = ret;
                     //return ret;
                     resolve(ret);
                  }
               );
         }
      );
   });
   return p;
};

// To generate Teep messages as test vectors:
// These are not APIs.
router.get('/testgen', function (req, res) {
   //sign and encrypt by TEEP agent key
   //QueryResponse
   let sampleRequest = { "TYPE": 2, "TOKEN": "1", "TA_LIST": [{ "Vendor_ID": "ietf-teep-wg" }] };

   //signAndEncrypt(sampleRequest);
   signAndEncrypt(sampleRequest).then((val) => {
      res.status(200);
      logger.debug(val)
      res.send(val);
      res.end();
   });
});

router.get('/testgen_cbor', function (req, res) {
   //sign and encrypt by TEEP agent key
   //QueryRequest
   //let sampleRequest = null; //{ 'TYPE': 2, 'TOKEN': '1', 'TA_LIST': "hoge" };
   //let values = Object.values(sampleRequest);
   //cbor.Map
   let cborRequest = new cbor.Map();
   cborRequest.set('TYPE', 2);
   let buf = new ArrayBuffer(1);
   let dv = new DataView(buf);
   dv.setUint8(0, 3);
   cborRequest.set('TOKEN', buf);
   cborRequest.set('TA_LIST', "hoge");

   let encoded = cbor.encode(cborRequest);
   //signAndEncrypt(sampleRequest);

   //outer_wrapper
   let outerWrapper = new cbor.Map();
   outerWrapper.set(1, null); //nil
   outerWrapper.set(2, cborRequest);
   res.send(cbor.encode(outerWrapper));
   res.end();
   // signAndEncrypt(sampleRequest).then((val) => {
   //    res.status(200);
   //    console.log(cborRequest);
   //    res.send(encoded);
   //    res.end();
   // });
});

router.get('/testgen_cose', function (req, res) {
   //console.log(ret);
   let ret = [6, 23456, 400];
   //let optMap = new cbor.Map();
   //optMap.set(8, ["11111", "22222"]);
   //ret.push(optMap);
   //let cborResponseArray = teepP.buildCborArray(ret);
   //console.log(cborResponseArray);
   let plainPayload = cbor.encode(ret);
   let headers = {
      'p': { 'alg': 'ES256' },
      'u': { 'kid': '' }
   };
   // @TODO switch using keyManager
   let TeePubKeyObj = JSON.parse(tee_pubkey.toString('utf8'));
   let signer = {
      'key': {
         'd': Buffer.from(TeePubKeyObj.d, 'base64') // TAM Priv Key
      }
   };
   cose.sign.create(headers, plainPayload, signer).then((buf) => {
      logger.debug(buf.toString('hex'));
      res.send(buf);
      res.end();
      return;
   });
});

router.get('/keycheck', function (req, res) {
   //console.log(keyManager.config);
   let tamPriv = keyManager.getKeyBinary("TAM_priv");
   logger.debug(tamPriv);
   res.send("").end();
   return;
});

module.exports = router;
