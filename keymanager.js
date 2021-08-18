/*
* Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
module.exports = {};

var fs = require('fs');
var configJson = require('./config.json');

var keyFilenameConfig = {
    "TAM_priv": "",
    "TAM_pub": "",
    "TEE_priv": "",
    "TEE_pub": ""
};

var keyChain = {
    "TAM_priv": null,
    "TAM_pub": null,
    "TEE_priv": null,
    "TEE_pub": null
};

module.exports.diag = () => {
    console.log("hogehoge");
    return;
}

module.exports.loadConfig = () => {
    console.log("Loading KeyConfig");
    keyFilenameConfig = configJson.key;
    console.log(keyFilenameConfig);
    return;
}

module.exports.saveConfig = () => {
    console.log("Save KeyConfig");
    configJson.key = keyFilenameConfig;
    fs.writeFileSync('./config.json', JSON.stringify(configJson, null, 2), function writeJSON(err) {
        if (err) {
            return console.log(err);
        }
        console.log("Success save config.json");
    })
    return;
}

module.exports.setKeyName = (keyName, val) => {
    if (!keyFilenameConfig.hasOwnProperty(keyName)) {
        console.log("ERR!: no such key " + keyName);
        return;
    }
    keyFilenameConfig[keyName] = val;
    return;
}

module.exports.getAllKeyName = () => {
    return keyFilenameConfig;
}

module.exports.loadKeyBinary = () => {
    Object.keys(keyFilenameConfig).forEach(function (x) {
        console.log("Load key " + x);
        keyChain[x] = fs.readFileSync("./key/" + keyFilenameConfig[x], function (err, data) {
            if (err) {
                console.log("ERR!: load key binary " + x);
                console.log(err);
                return;
            }
            console.log(data);
            //keyChain[x] = data;
            return;
        });
    });
    console.log("Key binary loaded");
    return;
}

module.exports.getKeyBinary = (keyName) => {
    if (!keyChain.hasOwnProperty(keyName)) {
        console.log("ERR!: no such key " + keyName);
        return;
    }
    return keyChain[keyName];
}
