var express = require('express');
var path = require('path');
var logger = require('morgan');
var http = require('http');

var apis = require('./routes/apis');
//var panels = require('./routes/panels');

var app = express();

app.use(logger('dev'));
app.use(express.static(path.join(__dirname, 'public')));
//app.set('views',path.join(__dirname,'views'));
//app.set('view engine','jade');

app.use('/api',apis);
//app.use('/panel',panels);

var listener = http.createServer(app).listen(8888, function(){
    console.log('Express HTTP server');
});

module.exports = app;

