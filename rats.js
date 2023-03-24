/*
* Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/

const cbor = require('cbor');
const cose = require('cose-js');
const fs = require('fs');
const crypto = require('crypto');
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
const mandatoryClaims = ['ueid', 'oemid', 'hwmodel', 'hwversion', 'manifests', 'cnf']; // ref. Section 5 in TEEP-Protocol
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

module.exports.verifyEAT = async (eat, kid = null) => {
    // See Section 7.1.1.1 in draft-ietf-teep-protocol-12
    try {
        let eat_buf = await cose.sign.verify(eat, verifyKey);
        let eat_payload = cbor.decodeFirstSync(eat_buf);
        // check and parse EAT format
        let eat_object = parseCborMapHelper(eat_payload);
        // mandatory claims check
        mandatoryClaims.forEach(x => {
            if (!eat_object.hasOwnProperty(x)) {
                logger.error(`Obtained EAT doesn't have a mandatory claim: ${x}`);
            }
        });
        // check cnf
        if (eat_object.cnf) {
            let isValidCnf = verifyCnf(eat_object.cnf);
            if (!isValidCnf) {
                logger.error("cnf claim in EAT isn't valid.");
            }else{
                logger.info("cnf in EAT is valid.");
            }
        }
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

const verifyCnf = function (payload, kid) {
    // payload as cnf defined RFC 8747
    if (payload.has(3)) { //3:kid
        let claimed_kid = Buffer.from(payload.get(3)).toString('hex'); // claimed_kid defined in TEEP EAT profile is hash of Agent public key
        logger.debug(`claimed_kid is:${claimed_kid}`);
        // Calculate TAM-holding Agent public key
        let keyObj;
        if (kid == null) {
            keyObj = JSON.parse(keyManager.getKeyBinary("TEE_pub").toString());
        } else {
            keyObj = JSON.parse(keyManager.getAgentKeyBinary(kid));
        }
        let keyX = Buffer.from(keyObj.x, 'base64');
        let keyY = Buffer.from(keyObj.y, 'base64');
        let concatKeyValue = keyX.toString('hex') + keyY.toString('hex');
        //logger.debug(concatKeyValue);
        const hash = crypto.createHash('sha256');
        hash.update(concatKeyValue,'hex');
        let hashVal = hash.digest('hex');
        logger.debug(`holding_key is:${hashVal}`);
        //compare claimed kid and calculated hash of holding Agent public key
        return claimed_kid === hashVal;
    } else if (payload.has(1) || payload.has(2)) { // 1:COSE_Key, 2:Encrypted_COSE_Key
        // TEEP EAT profie doesn't support these key types.
        return false;
    } else {
        logger.error("The claimed cnf isn't valid format.");
        return false;
    }
}