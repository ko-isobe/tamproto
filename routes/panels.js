var express = require('express');
var router = express.Router();
var jws = require('jws');
var fs = require('fs');

router.get('/', function (req, res, next) {
    var fileList;

    fs.readdir('./TAs', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        console.log(fileList);
        res.locals.files = fileList;
        res.render("./index.ejs");
    });

    //await makeRequest();
    //console.log(fileList);
    
});

module.exports = router;