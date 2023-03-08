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
    if (challenge === undefined || challenge === null){
        logger.error("No challenge is given.")
        return false
    }
    
    let buf = Buffer.from(challenge, 'hex');
    logger.debug(buf);
    const result = await Challenge.findOne({
        where: {
            token: buf
        }
    })
    if (result === null) {
        //doesn't match the received token
        logger.error("Received challenge is not found in Token Manager.")
        return false
    }
    if (result.isUsed) {
        // the received token is already used
        logger.error("Found the received challenge. But already used.")
        return false
    }
    // the received token is not used(=valid). Turn into the used token
    result.isUsed = true;
    await result.save();
    return true
}

module.exports.verifyEAT = async (eat) => {
    try {
        let eat_payload = await cose.sign.verify(eat, verifyKey);
        console.log(eat_payload);
        // check EAT format
        // check challenge
        this.consumeChallenge(eat_payload.challenge);
    } catch (e) {
        logger.error('verify error', e.toString());
    }

}