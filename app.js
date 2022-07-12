/*
* Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
var express = require('express');
var path = require('path');
//var logger = require('morgan');
const log4js = require('log4js');
const logger = log4js.getLogger('app.js');
logger.level = 'debug';
const log4jex = require('log4js-extend');
log4jex(log4js);

var http = require('http');
var https = require('https');
var fs = require('fs');
var bodyParser = require('body-parser');
const dns = require('dns');
const ip = require('ip');

var apis = require('./routes/apis');
var panels = require('./routes/panels');

var keyManager = require('./keymanager.js');

var app = express();

var opts = {
    key: fs.readFileSync('./key/TAM_ECkey.pem'),
    cert: fs.readFileSync('./key/TAM_ECcrt.pem'),
    ca: fs.readFileSync('./key/RootCA_crt.pem'),
    //requestCert:true,
    //rejectUnauthorized: false
};

app.use(log4js.connectLogger(log4js.getLogger('express')));
app.use(bodyParser.json({ type: 'application/*+json', inflate: false }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.raw({
    type: 'application/*+cbor',
    limit: '1mb'
}));
app.use(bodyParser.raw({
    type: 'application/*+cose',
    limit: '1mb'
}));
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

keyManager.loadConfig();
keyManager.loadKeyBinary();

app.use('/api', apis);
app.use('/panel', panels);
app.use('/TAs', express.static('TAs'));
app.use('/key', express.static('key'));

// app.use('/', function(req,res,next){
//     console.log("Root(/) request:");
//     console.log(req.headers);
//     console.log(req.body);

//     res.status(404);
//     var errorMsg = {"error":"Not found...."};
//     res.send(JSON.stringify(errorMsg));
// });

//
const setServIP = () => {
    return new Promise((resolve, reject) => {
        let ipAddress = null;
        dns.lookup('tam_srv_ip', (err, address, family) => {
            if (typeof address === "undefined") {
                ipAddress = ip.address();
            } else {
                ipAddress = address;
            }
            resolve(ipAddress);
        });
    })
};


setServIP().then(x => {
    logger.debug('server IpAddr set as:', x);
    module.exports.ipAddr = x;

    var listener = http.createServer(app).listen(8888, function () {
        logger.info('Express HTTP  server listening on port ' + listener.address().port);
    });

    var tls_listener = https.createServer(opts, app).listen(8443, function () {
        logger.info('Express HTTPS server listening on port ' + tls_listener.address().port);
    });

    module.exports = app;
});



