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
var rulesJson = require('./rules.json');

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

// Agent Public Key's
var agentPubKeyFilenames = {}
var agentPubKeys = {}; // kid => filename

module.exports.loadConfig = () => {
    logger.info("Loading KeyConfig");
    keyFilenameConfig = configJson.key;
    // rulesJson format check is needed
    Object.keys(rulesJson).forEach(function (x) {
        agentPubKeyFilenames[x] = rulesJson[x].key;
    });
    logger.debug(agentPubKeyFilenames);
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
    // Agent Public Key binary loading
    Object.keys(agentPubKeyFilenames).forEach(function (x) {
        logger.info("Load Agent key " + x);
        let keyString = fs.readFileSync("./key/" + agentPubKeyFilenames[x], function (err, data) {
            if (err) {
                logger.error("load Agent Public key string " + x);
                logger.error(err);
                return;
            }
            logger.debug(data);
        });
        let keyObj = JSON.parse(keyString);
        if (keyObj.hasOwnProperty("kid")) {
            agentPubKeys[keyObj.kid] = keyString;
        } else {
            logger.warn("Following Agent Public key doen't have kid. " + x);
            agentPubKeys[x] = keyString; // temporary
        }
    })
    //logger.debug(agentPubKeys);
    return;
}

module.exports.getKeyBinary = (keyName) => {
    if (!keyChain.hasOwnProperty(keyName)) {
        logger.error("no such key " + keyName);
        return;
    }
    return keyChain[keyName];
}

module.exports.isStoredAgentKey = (kid) => {
    return agentPubKeys.hasOwnProperty(kid);
}

module.exports.getAgentKeyBinary = (kid) => {
    if (!agentPubKeys.hasOwnProperty(kid)) {
        logger.error("no such Agent Public key " + kid);
        return;
    }
    return agentPubKeys[kid];
}