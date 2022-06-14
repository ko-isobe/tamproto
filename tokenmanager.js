/*
* Copyright (c) 2022 SECOM CO., LTD. All Rights reserved.
*
* SPDX-License-Identifier: BSD-2-Clause
*/
const sqlite3 = require('sqlite3');
const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize('sqlite::memory:') // Example for sqlite
const { randomFillSync } = require('crypto')

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
    buf = Buffer.from([0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF]);
    console.log("Generated randomBytes :" + buf.toString('hex'));
    return buf;
}

module.exports.generateToken = async () => {
    const token = await Token.create({ token: generateRandomBytes(), isUsed: false });
    //token.then(function(result){
    console.log(token.toJSON())
    return await token.token
    //})
}

// Token verify and set used flag if unused
module.exports.consumeToken = async (token) => {
    let buf = Buffer.from(token,'hex');
    console.log(buf);
    const result = await Token.findOne({
        where: {
            token:buf
        }
    })
    if (result === null) {
        //doesn't match the received token
        console.log("ERR!: Received token is not found in Token Manager.")
        return false
    }
    if (result.isUsed) {
        // the received token is already used
        console.log("ERR!: Found the received token. But already used.")
        return false
    }
    // the received token is not used(=valid). Turn into the used token
    result.isUsed = true;
    await result.save();
    return true

}

//get All tokens to show token's table
module.exports.getAllTokens = async () => {
    const result = await Token.findAll({raw:true});
    console.log(result)
    return result;
}