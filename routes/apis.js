var express = require('express');
var router = express.Router();
var jws = require('jws');
var otrp = require('../otrp.js');
var jose = require('node-jose');
var fs = require('fs');

var keystore = jose.JWK.createKeyStore();
var tee_pubkey = fs.readFileSync("./key/spaik-pub.jwk", function (err, data) {
   console.log(data);
});

var tam_privkey = fs.readFileSync("./key/tam-mytam-rsa-key.pem", function (err, data) {
   console.log(data);
});

var jwk_tam_privkey, jwk_tee_pubkey;

keystore.add(tee_pubkey, "json").then(function (result) {
   jwk_tee_pubkey = result;
});
keystore.add(tam_privkey, "pem").then(function (result) {
   jwk_tam_privkey = result;
});

router.get('/', function (req, res, next) {
   var param = { "key": "This is sample" };
   res.header('Content-Type', 'application/json; charset=utf-8');
   res.send(param);
});

//var teepImplReturn = true;

router.post('/tam', function (req, res, next) {
   // check POST content
   console.log(req.headers);
   console.log(req.body);

   var let = null;
   //set response header
   res.set({
      'Content-Type': 'application/teep+json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'",
      'Referrer-Policy': 'no-referrer'
   });

   //if (!Object.keys(req.body).length) {
   if(req.headers['content-length']==0){
      // body is empty
      console.log("TAM API launch");
      //Call OTrP Implementation's ProcessConnect API
      //let = otrp.init();

      //Dummy GetDeviceStateTBSRequest
      var teepObj = {
         "GetDeviceStateTBSRequest": {
            "ver": "1.0",
            "rid": "000000",
            "tid": "000001",
            "ocspdat": "0x0000",
         }
      };
      res.send(JSON.stringify(teepObj));
      return;
   } else {
      console.log("TAM ProcessOTrPmessage launch");
      console.log(req.body);
      //dummy install message
      //var tanameObj = JSON.parse(req.body);
      var tanameObj = req.body;
      if ("taname" in tanameObj && fs.existsSync('./TAs/'+tanameObj['taname'])) {
         // ta install
         console.log(tanameObj['taname']);
         var f_pt = fs.readFileSync("./TAs/" + tanameObj['taname'], function (err, data) {
            console.log(err);
         });

         jose.JWE.createEncrypt({ alg: 'RSA1_5', contentAlg: 'A128CBC-HS256', format: "flattened" }, jwk_tee_pubkey)
            .update(f_pt).final().then(function (result) {
               f = JSON.stringify(result);

               jose.JWS.createSign({ alg: 'RS256', format: 'flattened' }, jwk_tam_privkey)
                  .update(f).final().then(function (result) {
                     f = JSON.stringify(result);
                     res.statusCode = 200;
                     res.set({
                        'Content-Type': 'application/teep+json',
                        'Cache-Control': 'no-store',
                        'X-Content-Type-Options': 'nosniff',
                        'Content-Security-Policy': "default-src 'none'",
                        'Referrer-Policy': 'no-referrer'
                     });
                     res.setHeader('Content-Length', f.length);
                     res.end(f);
                  });
            });

         return;
      } else {
         // Call OTrP Implementation's
         //let = otrp.handleMessage();
         console.log("no content");
         res.set(null);
         res.status(204).send('no content');
      }
      return;
   }
});

router.post('/install', function (req, res, next) {
   // check POST content
   console.log(req.headers);
   console.log(req.body);
   var f_pt = fs.readFileSync("./TAs/dummy2.ta", function (err, data) {
      console.log(err);
   });

   jose.JWE.createEncrypt({ alg: 'RSA1_5', contentAlg: 'A128CBC-HS256', format: "flattened" }, jwk_tee_pubkey)
      .update(f_pt).final().then(function (result) {
         f = JSON.stringify(result);

         jose.JWS.createSign({ alg: 'RS256', format: 'flattened' }, jwk_tam_privkey)
            .update(f).final().then(function (result) {
               f = JSON.stringify(result);
               res.statusCode = 200;
               res.set({
                  'Content-Type': 'application/teep+json',
                  'Cache-Control': 'no-store',
                  'X-Content-Type-Options': 'nosniff',
                  'Content-Security-Policy': "default-src 'none'",
                  'Referrer-Policy': 'no-referrer'
               });
               res.setHeader('Content-Length', f.length);
               res.end(f);
            });
      });
});

router.post('/delete', function (req, res, next) {
   // check POST content
   console.log(req.headers);
   console.log(req.body);

   var cmd = "{\"delete-ta\":\"8d82573a-926d-4754-9353-32dc29997f74.ta\"}";
   console.log("Request for delete packet\n");

   jose.JWE.createEncrypt({ alg: 'RSA1_5', contentAlg: 'A128CBC-HS256', format: "flattened" },
      jwk_tee_pubkey).update(cmd).final().then
      (function (result) {
         f = JSON.stringify(result);

         jose.JWS.createSign({ alg: 'RS256', format: 'flattened' }, jwk_tam_privkey).update(f).final().then
            (function (result) {
               f = JSON.stringify(result);
               res.statusCode = 200;
               res.set({
                  'Content-Type': 'application/teep+json',
                  'Cache-Control': 'no-store',
                  'X-Content-Type-Options': 'nosniff',
                  'Content-Security-Policy': "default-src 'none'",
                  'Referrer-Policy': 'no-referrer'
               });
               res.setHeader('Content-Length', f.length);
               res.end(f);
            });
      });
});

module.exports = router;