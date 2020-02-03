var express = require('express');
var router = express.Router();
var jws = require('jws');
var fs = require('fs');
var multer = require('multer');
var storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './TAs');
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});
var keystorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './key');
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});
var upload = multer({ storage: storage });
var keyupload = multer({ storage: keystorage });
var jose = require('node-jose');

let keyStore = jose.JWK.createKeyStore();

router.get('/', function (req, res, next) {
    var fileList;
    res.locals.fullURL = req.protocol + '://' + req.get('host');
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

router.get('/upload', function (req, res) {
    res.redirect('/panel/');
});

router.post('/upload', upload.single('file'), function (req, res, next) {
    res.locals.status = "uploaded";
    res.locals.fullURL = req.protocol + '://' + req.get('host');
    //res.locals.delURL = req.protocol + '://' + req.get('host') + '/panel/delete';
    fs.readdir('./TAs', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        console.log(fileList);
        res.locals.files = fileList;
        res.render("./index.ejs");
    });
});

router.get('/delete', function (req, res) {
    var delTAname = req.query.taname;
    if (delTAname != '' && fs.existsSync('./TAs/' + delTAname)) {
        fs.unlinkSync('./TAs/' + delTAname);
        console.log("deleted TA:" + delTAname);
    }

    res.locals.fullURL = req.protocol + '://' + req.get('host');
    fs.readdir('./TAs', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        console.log(fileList);
        res.locals.files = fileList;
        res.render("./index.ejs");
    });
});

// Key Manage UI
router.get('/keys', function (req, res, next) {
    var fileList;
    res.locals.fullURL = req.protocol + '://' + req.get('host');
    fs.readdir('./key', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        console.log(fileList);
        res.locals.files = fileList;
        res.render("./keymanage.ejs");
    });

    //await makeRequest();
    //console.log(fileList);

});

router.post('/key_upload', keyupload.single('file'), function (req, res, next) {
    res.locals.status = "uploaded";
    res.locals.fullURL = req.protocol + '://' + req.get('host');
    //res.locals.delURL = req.protocol + '://' + req.get('host') + '/panel/delete';
    fs.readdir('./key', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        console.log(fileList);
        res.locals.files = fileList;
        res.render("./keymanage.ejs");
    });
});

router.get('/key_delete', function (req, res) {
    var delKeyName = req.query.keyname;
    if (delKeyName != '' && fs.existsSync('./key/' + delKeyName)) {
        fs.unlinkSync('./key/' + delKeyName);
        console.log("deleted Key:" + delKeyName);
    }

    res.locals.fullURL = req.protocol + '://' + req.get('host');
    fs.readdir('./key', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        console.log(fileList);
        res.locals.files = fileList;
        res.render("./keymanage.ejs");
    });
});

router.get('/key_detail', function (req, res) {
    var keyName = req.query.keyname;
    res.locals.keyname = keyName;
    let promise = null;
    if (keyName != '' && fs.existsSync('./key/' + keyName)) {
        //fs.unlinkSync('./key/'+KeyName);
        console.log("detailed Key:" + keyName);
        let content = new String();
        content = fs.readFileSync('./key/' + keyName, 'utf8');
        console.log(content);
        if (keyName.endsWith('.pem')){
            promise = jose.JWK.asKey(content, "pem");
        } else {
            promise = jose.JWK.asKey(content);
        }
    } else {
        console.log("No key found or invalid parameter");
        res.locals.err = "No key found or invalid parameter";
        res.render("./keydetail.ejs");
        return;
    }
    promise.then(function (result) {
        console.log(result);
        res.locals.ret = JSON.stringify(result,null,'\t');
        res.render("./keydetail.ejs");
    },function(err){
        console.log(err);
        res.render("./keydetail.ejs");
    });
});

module.exports = router;