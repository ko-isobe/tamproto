var express = require('express');
var router = express.Router();
var jws = require('jws');

router.get('/',function(req,res,next){
    res.render("./index.ejs");
});

module.exports = router;