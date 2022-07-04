/*
* Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
const sqlite3 = require('sqlite3');
const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize('sqlite::memory:', {
    logging: (log) => { sequelize_logger.debug(log) }
}); // Example for sqlite
const { randomFillSync } = require('crypto');
const log4js = require('log4js');
const logger = log4js.getLogger('tokenmanager.js');
logger.level = 'info';
const sequelize_logger = log4js.getLogger('Sequelize');
sequelize_logger.level = 'info';

const Token = sequelize.define('Token', {
    token: {
        type: DataTypes.BLOB,
        allowNull: false
    },
    isUsed: {
        type: DataTypes.BOOLEAN
    }
});

Token.sync();

const generateRandomBytes = () => {
    let buf = Buffer.alloc(8);
    randomFillSync(buf);
    buf = Buffer.from([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF]);
    logger.info("Generated randomBytes :" + buf.toString('hex'));
    return buf;
}

module.exports.generateToken = async () => {
    const token = await Token.create({ token: generateRandomBytes(), isUsed: false });
    //token.then(function(result){
    logger.debug('new Token record:', token.toJSON())
    return await token.token
    //})
}

// Token verify and set used flag if unused
module.exports.consumeToken = async (token) => {
    let buf = Buffer.from(token, 'hex');
    logger.debug(buf);
    const result = await Token.findOne({
        where: {
            token: buf
        }
    })
    if (result === null) {
        //doesn't match the received token
        logger.error("Received token is not found in Token Manager.")
        return false
    }
    if (result.isUsed) {
        // the received token is already used
        logger.error("Found the received token. But already used.")
        return false
    }
    // the received token is not used(=valid). Turn into the used token
    result.isUsed = true;
    await result.save();
    return true

}

//get All tokens to show token's table
module.exports.getAllTokens = async () => {
    const result = await Token.findAll({ raw: true });
    logger.debug(result);
    return result;
}