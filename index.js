const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const util = require('util');

const verifyToken = async token => {
    const decoded = jwt.decode(token, { complete: true }); // complete is decode include header
    if (!decoded || !decoded.header || !decoded.header.kid) {
        throw new jwt.JsonWebTokenError('invalid token');
    }
    const jwksClientParam = { // setting: https://github.com/auth0/node-jwks-rsa#usage
        jwksUri: process.env.JWKS_URI,
    }
    const client = jwksClient(jwksClientParam);
    const getSigningKey = util.promisify(client.getSigningKey);
    const signingKey = await getSigningKey(decoded.header.kid).catch(e => { throw e }); // await exception catch rethrow
    const publicKey = signingKey.getPublicKey();
    const jwtVerifyParam = { // setting: https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
        issuer: process.env.TOKEN_ISSUER
    }
    const verify = util.promisify(jwt.verify);
    const tokenPayload = await verify(token, publicKey, jwtVerifyParam);
    return tokenPayload;
};
exports.handler = async (token) => {
    try {
        const tokenPayload = await verifyToken(token);
        return tokenPayload
    } catch (err) {
        console.error(err);
        return err;
    }
}
