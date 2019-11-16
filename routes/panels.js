var express = require('express');
var router = express.Router();
var jws = require('jws');
var fs = require('fs');
var multer = require('multer');
var storage = multer.diskStorage({
    destination: function(req,file,cb){
        cb(null,'./TAs');
    },
    filename: function(req,file,cb){
        cb(null,file.originalname);
    }
});
var upload = multer({ storage:storage });

router.get('/', function (req, res, next) {
    var fileList;
    res.locals.fullURL = req.protocol + '://' + req.get('host') + '/TAs/';
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

router.get('/upload',function(req,res){
    res.redirect('/panel/');
});

router.post('/upload', upload.single('file'), function (req, res, next) {
    res.locals.status = "uploaded";
    res.locals.fullURL = req.protocol + '://' + req.get('host') + '/TAs/';
    res.locals.delURL = req.protocol + '://' + req.get('host') + '/panel/delete';
    fs.readdir('./TAs', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        console.log(fileList);
        res.locals.files = fileList;
        res.render("./index.ejs");
    });
});

router.get('/delete',function(req,res){

});

module.exports = router;