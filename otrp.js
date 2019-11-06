
var init = function(){
    console.log("called otrp init");

    return false;
}

var otrp = new Object();
otrp.init = init;

module.exports = otrp;