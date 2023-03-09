/*
* Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/

const cbor = require('cbor');
var cose = require('cose-js');
const fs = require('fs');
//const { request } = require('./app');
const keyManager = require('./keymanager.js');
const log4js = require('log4js');
const logger = log4js.getLogger('rats.js');
logger.level = 'debug';

//ref. CWT claims in IANA Registry
const claimsArray = {
    'iss': 1, 'sub': 2, 'aud': 3, 'exp': 4, 'nbf': 5, 'iat': 6, 'jti': 7, 'cnf': 8, 'scope': 9, 'nonce': 10,
    'ueid': 256, 'sueids': 257, 'oemid': 258, 'hwmodel': 259, 'hwversion': 260, 'secboot': 262, 'dbgstat': 263, 'eat_profile': 265,
    'verifier_challenge': -70000 // Private use for s-miyazawa/teep_armadilo_trial
};
const claimsNametoKey = new Map(Object.entries(claimsArray));
//console.log(claimsNametoKey);

// Database for storing challenge
const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize('sqlite::memory:', {
    logging: (log) => { sequelize_logger.debug(log) }
}); // Example for sqlite
const { randomFillSync } = require('crypto');
const sequelize_logger = log4js.getLogger('Sequelize');
sequelize_logger.level = 'info';

const Challenge = sequelize.define('Challenge', {
    challenge: {
        type: DataTypes.BLOB,
        allowNull: false
    },
    isUsed: {
        type: DataTypes.BOOLEAN
    },
});

Challenge.sync();

const VerifyKeyObj = JSON.parse(keyManager.getKeyBinary("Verify").toString());

const verifyKey = {
    'key': {
        'x': Buffer.from(VerifyKeyObj.x, 'base64'),
        'y': Buffer.from(VerifyKeyObj.y, 'base64')
    }
};

//==============================================================================

const generateRandomBytes = () => {
    let buf = Buffer.alloc(8);
    randomFillSync(buf);
    //buf = Buffer.from([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF]);
    //buf = Buffer.from([0xAB, 0xCD, 0x88, 0x60, 0xD1, 0x3A, 0x46, 0x3E, 0x8E]); //static challenge for debugging
    logger.info("Generated randomBytes :" + buf.toString('hex'));
    return buf;
}

module.exports.generateChallenge = async () => {
    const new_challenge = await Challenge.create({ challenge: generateRandomBytes(), isUsed: false });
    //Challenge.then(function(result){
    logger.debug('new Challenge record:', new_challenge.toJSON())
    return await new_challenge.challenge
    //})
}

//get All tokens to show token's table
module.exports.getAllChallenges = async () => {
    const result = await Challenge.findAll({ raw: true });
    logger.debug(result);
    return result;
}

// Token verify and set used flag if unused
module.exports.consumeChallenge = async (challenge) => {
    if (challenge === undefined || challenge === null) {
        logger.error("No challenge is given.")
        return false
    }

    let buf = Buffer.from(challenge, 'hex');
    logger.debug(buf);
    const result = await Challenge.findOne({
        where: {
            challenge: buf
        }
    })
    if (result === null) {
        //doesn't match the received token
        logger.error("Received challenge is not found in Challenge Manager. :" + challenge)
        return false
    }
    if (result.isUsed) {
        // the received token is already used
        logger.error("Found the received challenge. But already used. :" + challenge)
        return false
    }
    // the received token is not used(=valid). Turn into the used token
    result.isUsed = true;
    await result.save();
    return true
}

module.exports.verifyEAT = async (eat) => {
    try {
        let eat_buf = await cose.sign.verify(eat, verifyKey);
        let eat_payload = cbor.decodeFirstSync(eat_buf);
        //logger.debug(eat_payload);
        // check and parse EAT format
        let eat_object = parseCborMapHelper(eat_payload);
        // check challenge
        let isValidChallenge = await this.consumeChallenge(eat_object.nonce);
        return eat_object;
    } catch (e) {
        logger.error('verify error', e.toString());
    }
}

const parseCborMapHelper = function (obj) {
    // obj as Map
    let ret = new Object();
    obj.forEach(function (value, key) {
        let claimName = findByClaimKey(key)
        if (claimName !== 0) { // whether found a valid EAT Claim Name
            if (Buffer.isBuffer(value)) {
                ret[claimName] = value.toString('hex'); // buffer => string
            } else {
                ret[claimName] = value;
            }
        }
    });
    logger.debug(ret);
    return ret;
}

const findByClaimKey = function (claimKey) {
    let searchKey = 0; // 0 is reserved.
    for (const [key, value] of claimsNametoKey.entries()) {
        if (value === claimKey) {
            searchKey = key;
            break;
        }
    }
    return searchKey;
}
