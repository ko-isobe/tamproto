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
    //buf = Buffer.from("abcdefgh");
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
    const result = await Token.findOne({
        where: {
            token: token
        }
    })
    if (result === null) {
        //doesn't match the received token
        return false
    }
    if (result.isUsed) {
        // the received token is already used
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
    return result;
}