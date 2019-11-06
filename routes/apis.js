 var express = require('express');
 var router = express.Router();
 var jws = require('jws');
 var otrp = require('../otrp.js');

 router.get('/',function(req,res,next){
    var param = {"値":"This is sample"};
    res.header('Content-Type','application/json; charset=utf-8');
    res.send(param);
 });

 var teepImplReturn = true;

 router.post('/tam',function(req,res,next){
   // check POST content
      console.log(req.headers);
      console.log(req.body);
      
   var let = null;
      if(!Object.keys(req.body).length){
         // body is empty
         console.log("TAM API launch");
         let = otrp.init();
      }else{
         console.log("TAM ProcessOTrpmessage launch");
      }
   // pass the TAM's OTrP Implementation (ProcessConnect?)

   //teepImplReturn = true;

   //GetDeviceStateTBSRequest
   var teepObj = {
      "GetDeviceStateTBSRequest":{
      "ver":"1.0",
      "rid" : "000000",
      "tid" : "000001",
      "ocspdat" : "0x0000",
      }
   };

   
   //var teepSignedObj = jws.sign({
   //   header: {alg:},
   //})

   // response 

   res.set({
      'Content-Type':'application/teep+json',
      'Cache-Control':'no-store',
      'X-Content-Type-Options':'nosniff',
      'Content-Security-Policy': "default-src 'none'",
      'Referrer-Policy':'no-referrer'
   });
   if(teepImplReturn){
      res.send(JSON.stringify(teepObj));
      teepImplReturn=false;
   }else{
      res.set(null);
      res.status(204).send('no content');
   }

 });

 module.exports = router;