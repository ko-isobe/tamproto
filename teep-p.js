//var textenc = require('text-encoding');
const cose = require('cose-js');

var init = function(){
    console.log("called TEEP-P init");
    /*
    // QueryRequest
    var token = Buffer.from('tamtokentest').toString('hex');
    var queryRequest = {
        "TYPE":1,
        "TOKEN":token,
        "REQUEST":[2],
        "CIPHER_SUITE": [1]
    };

    // sign
    const headers = {
        'p': {'alg':'RS256'},
        'u': {'kid': '11'}
    };
    const signer = {
        "key": {"p":"7cILq1tVaaQdND-Aeq26SCsYlGNcb4NFyVnK8XckwoHnLOuO8jRJCe33HwDOXhlaC36wQgDTftngooEEPGLfQw2EkbmjbPmNxvm6daPTrbpRTXBHSiEXJBaAqjHEXiIy8X5XS6WiIRC7xiocF7P34yJaUsY3sM34t1H_mC0-x18","kty":"RSA","q":"1V9Jkmflf4i9uy-XK72965iW1blzy9X_CPcggo5dIR5wTxm7lAwgYBWec60CxiHZqiEr7ifcv-u9DugXrrCCW_871KYO6N8nWdW3PZOiH-Xd6VYT1ZPbRKB9Rr6WgthC_AsQWFA5TBR3LS_5CaBbl5Hh916blGkNOqFZlRVzGlk","d":"pVU0Dl4WCXR7W6YlVQzn-TddwKK4pGMmXOgYWM1CgYijNs24QPksGx_5wOEvswa04XBGoVAa81kNpMvI-Q25J7LxnAlkzVVj4EJ0GBAVQ5idXxp_PRwFKYFQKfAWmlxhcqb1dLIfXvkcuedZPHxfYqaNnStWCtAYgnfVF50Y97Lp4ZVX5WU4j3PZZHZ_r-zOoelJFsEeBXmKYxGIRCx2hiTyOMiprsLpIzjnKvSF5dVYhp665M-uo_6-KPfPGjMXVoiCYfoiggd85uiJYQrYp36rMnMdO5WnOif6ixjOXps3ZgrPPVzFzKFhkk84_aJs8FKT_CadbqppCeIbKkV24Q","e":"AQAB","kid":"f13d7c73-06e7-4ce7-8bbd-137442b352f3","qi":"KlkLp8Y_KKmxczDqGCNysxd_O0k3QQii5Wi96ZYHEw8IVfaeqTrMMgfNASVGQ2gY5KmEMqxlZCfLJQ4CqZ-vcRob_xRtYbFGdjCDqspK2DqwagcKtcUr5BH0nXwWsLR8-KBeJ16Jqup01oXXs0KDuXiROeDRihe1yJGRCiwas08","dp":"HpQ_hfmIQb8O1oJ4Vs7zT4bjcWpaICmFF0GKPYYyXyXwArIFP5eD8Vf-2ajz4dxm3WWc69BJY15Iav4m-lFJH8mkTE3Q_BoYpwfFeI3qksSM4mXXdWxOGqEeSUV_WRAS90ZlmeAiuxf43qLZ3B6Uek0Xyt-dmArVu1Y7hmoDUgc","dq":"yQXtGrIn1e_OUPyVP_CTbdNkyBbgsbn7fUbWqinWM82podxsjR6foea8Ud8-LczWdSKrcMS9hVNj2xduuHYzWtksVTvd8CfNuyVObgUZSVQXri4aoa2bdxx86pnE06FL-omx7IIoeTUO0tPPnPInWLVoXtYTXc9bV1GMRJjgyIE","n":"xirzDDYRshXXJ7z1f9GKgvXpBV4kMluvghEfg4YPVRrGYZhWSqys8-4oEBUNg1vecL82Hxna4P8AsTWZE2fAzN04HPefi7XhhNG8DGrZNCzWxPW9HwAdF2l5Oycr-Zvq6G7U7wo8LXkyGggy4fo7Ma9D_XUcWsilkOOw2obJcLN1j9ec0bPdQhNk7wy7gmKmKqtMj2tW3NbQS9zjo1IgipsJlUGL7sx3EWMJqmEDPm3S1vaXkmQYZak9S_WEZoPahKyqQU3E6aMw9wXUQonqXXtrtHQfv1-DBGPtQ49G2t_OP5l2ZXmbZBCC1WsY1LsOZSoUCICTYapuIttZdb_2Bw"
        }
    };

    cose.sign.create(
        headers,
        queryRequest,
        signer
    ).then((buf) => {
        console.log(buf.toString('hex'));
    }).catch((error)=>{
        console.log(error);
    });

    //var msg_authenc_wrapper = 
    */
    return false;
}

var queryRequest = new Object();
queryRequest.type = 1; // TYPE = 1 corresponds to a QueryRequest message sent from the TAM to the TEEP Agent.
queryRequest.token = 'hoge'; // The value in the TOKEN field is used to match requests to responses.
queryRequest.request = [2]; // request Trusted Apps lists for device


var teepp  = new Object();
teepp.init = init;
teepp.queryRequest = queryRequest;

module.exports = teepp;