var express = require('express');
var path = require('path');
var logger = require('morgan');
var http = require('http');
var https = require('https');
var fs = require('fs');
var bodyParser = require('body-parser');

var apis = require('./routes/apis');
var panels = require('./routes/panels');

var app = express();

var opts = {
    key: fs.readFileSync('./key/TAM_key.pem'),
    cert: fs.readFileSync('./key/TAM_cert.pem'),
    ca: fs.readFileSync('./key/RootCA_crt2.pem'),
    //requestCert:true,
    //rejectUnauthorized: false
  };

app.use(logger('dev'));
app.use(bodyParser.json({type:'application/*+json',inflate:false}));
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname, 'public')));
app.set('views',path.join(__dirname,'views'));
app.set('view engine','ejs');

app.use('/api',apis);
app.use('/panel',panels);
app.use('/TAs',express.static('TAs'));
app.use('/key',express.static('key'));

// app.use('/', function(req,res,next){
//     console.log("Root(/) request:");
//     console.log(req.headers);
//     console.log(req.body);

//     res.status(404);
//     var errorMsg = {"error":"Not found...."};
//     res.send(JSON.stringify(errorMsg));
// });

var listener = http.createServer(app).listen(8888, function(){
    console.log('Express HTTP  server listening on port ' + listener.address().port);
});

var tls_listener = https.createServer(opts, app).listen(8433, function () {
    console.log('Express HTTPS server listening on port ' + tls_listener.address().port);
});

module.exports = app;

