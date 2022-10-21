/*
* Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
var express = require('express');
var router = express.Router();
//var jws = require('jws');
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
var keyManager = require('../keymanager.js');
var tokenManager = require('../tokenmanager.js');
var rats = require('../rats.js');

const log4js = require('log4js');
const logger = log4js.getLogger('panels.js');
logger.level = 'debug';
//var nconf = require('nconf');
//nconf.use('file', { file: './config.json' });
//nconf.load();
//console.log(nconf);

let keyStore = jose.JWK.createKeyStore();

router.get('/', function (req, res, next) {
    var fileList;
    res.locals.fullURL = req.protocol + '://' + req.get('host');
    fs.readdir('./TAs', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        logger.debug(fileList);
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
        logger.debug(fileList);
        res.locals.files = fileList;
        res.render("./index.ejs");
    });
});

router.get('/delete', function (req, res) {
    var delTAname = req.query.taname;
    if (delTAname != '' && fs.existsSync('./TAs/' + delTAname)) {
        fs.unlinkSync('./TAs/' + delTAname);
        logger.info("deleted TA:" + delTAname);
    }

    res.locals.fullURL = req.protocol + '://' + req.get('host');
    fs.readdir('./TAs', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        logger.debug(fileList);
        res.locals.files = fileList;
        res.render("./index.ejs");
    });
});

// Key Manage UI
const getKeysList = (req, res, next) => {
    //common middleware - collect key files and URL setting
    res.locals.fullURL = req.protocol + '://' + req.get('host');
    //load key config
    // res.locals.key_TAMpriv = nconf.get('key:TAM_priv');
    // res.locals.key_TAMpub = nconf.get('key:TAM_pub');
    // res.locals.key_TEEpriv = nconf.get('key:TEE_priv');
    // res.locals.key_TEEpub = nconf.get('key:TEE_pub');
    let configs = keyManager.getAllKeyName();
    res.locals.key_TAMpriv = configs.TAM_priv;
    res.locals.key_TAMpub = configs.TAM_pub;
    res.locals.key_TEEpriv = configs.TEE_priv;
    res.locals.key_TEEpub = configs.TEE_pub;
    res.locals.key_Verify = configs.Verify;
    //collect key files
    fs.readdir('./key', { withFileTypes: true }, function (err, files) {
        if (err) throw err;
        fileList = files;
        logger.debug(fileList);
        res.locals.files = fileList;
        next();
    });
};

router.get('/keys', getKeysList, function (req, res, next) {
    res.render("./keymanage.ejs");
    return;
});

router.post('/key_upload', keyupload.single('file'), getKeysList, function (req, res, next) {
    res.locals.status = "uploaded";
    res.render("./keymanage.ejs");
});

router.get('/key_delete', getKeysList, function (req, res) {
    // TODO: deleted key is not reflected getKeysList
    var delKeyName = req.query.keyname;
    if (delKeyName != '' && fs.existsSync('./key/' + delKeyName)) {
        fs.unlinkSync('./key/' + delKeyName);
        logger.info("deleted Key:" + delKeyName);
    }
    res.render("./keymanage.ejs");
});

router.post('/key_config', getKeysList, function (req, res) {
    // nconf.set('key:TAM_priv', req.body.tam_priv);
    // nconf.set('key:TAM_pub', req.body.tam_pub);
    // nconf.set('key:TEE_priv', req.body.tee_priv);
    // nconf.set('key:TEE_pub', req.body.tee_pub);
    // console.log(nconf.get('key'));
    // //nconf.save();
    //new keyManager
    keyManager.setKeyName("TAM_priv", req.body.tam_priv);
    keyManager.setKeyName("TAM_pub", req.body.tam_pub);
    keyManager.setKeyName("TEE_priv", req.body.tee_priv);
    keyManager.setKeyName("TEE_pub", req.body.tee_pub);
    keyManager.setKeyName("Verify", req.body.verifier);
    keyManager.saveConfig();
    keyManager.loadKeyBinary();
    //load key config
    let configs = keyManager.getAllKeyName();
    res.locals.key_TAMpriv = configs.TAM_priv;
    res.locals.key_TAMpub = configs.TAM_pub;
    res.locals.key_TEEpriv = configs.TEE_priv;
    res.locals.key_TEEpub = configs.TEE_pub;
    res.locals.key_Verify = configs.Verify;
    res.render("./keymanage.ejs");
});

// Key Detail UI
router.get('/key_detail', function (req, res) {
    var keyName = req.query.keyname;
    res.locals.keyname = keyName;
    let promise = null;
    if (keyName != '' && fs.existsSync('./key/' + keyName)) {
        //fs.unlinkSync('./key/'+KeyName);
        logger.info("detailed Key:" + keyName);
        let content = new String();
        content = fs.readFileSync('./key/' + keyName, 'utf8');
        logger.debug(content);
        if (keyName.endsWith('.pem')) {
            promise = jose.JWK.asKey(content, "pem");
        } else {
            promise = jose.JWK.asKey(content);
        }
    } else {
        logger.error("No key found or invalid parameter");
        res.locals.err = "No key found or invalid parameter";
        res.render("./keydetail.ejs");
        return;
    }
    promise.then(function (result) {
        logger.debug(result.toJSON(true));
        res.locals.ret = JSON.stringify(result.toJSON(true), null, '\t'); //disclose private key
        res.render("./keydetail.ejs");
    }, function (err) {
        logger.error(err);
        res.render("./keydetail.ejs");
    });
});

// Token Table UI
router.get('/token', async function (req, res) {
    let obj = await tokenManager.getAllTokens();
    res.locals.tokens = obj;
    res.render("./token.ejs");
});

// Challenge Table UI
router.get('/challenge', async function (req, res) {
    let obj = await rats.getAllChallenges();
    res.locals.challenges = obj;
    res.render("./challenge.ejs");
});

module.exports = router;