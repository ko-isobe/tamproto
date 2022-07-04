/*
* Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
module.exports = {};

var fs = require('fs');
const log4js = require('log4js');
const logger = log4js.getLogger('keymanager.js');
logger.level = 'debug';
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
    logger.info("Loading KeyConfig");
    keyFilenameConfig = configJson.key;
    logger.debug(keyFilenameConfig);
    return;
}

module.exports.saveConfig = () => {
    logger.info("Save KeyConfig");
    configJson.key = keyFilenameConfig;
    fs.writeFileSync('./config.json', JSON.stringify(configJson, null, 2), function writeJSON(err) {
        if (err) {
            return logger.error(err);
        }
        logger.info("Success save config.json");
    })
    return;
}

module.exports.setKeyName = (keyName, val) => {
    if (!keyFilenameConfig.hasOwnProperty(keyName)) {
        logger.error("no such key " + keyName);
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
        logger.info("Load key " + x);
        keyChain[x] = fs.readFileSync("./key/" + keyFilenameConfig[x], function (err, data) {
            if (err) {
                logger.error("load key binary " + x);
                logger.error(err);
                return;
            }
            logger.debug(data);
            //keyChain[x] = data;
            return;
        });
    });
    logger.info("Key binary loaded");
    return;
}

module.exports.getKeyBinary = (keyName) => {
    if (!keyChain.hasOwnProperty(keyName)) {
        logger.error("no such key " + keyName);
        return;
    }
    return keyChain[keyName];
}
