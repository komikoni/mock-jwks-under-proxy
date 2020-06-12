'use strict';

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const createJWKSMock = require('mock-jwks').default;
const issureHost = "auth.example.com";
const issureUri = `http://${issureHost}`
const jwks = createJWKSMock(issureUri);

const consoleLog = jest.spyOn(console, 'log');
const consoleError = jest.spyOn(console, 'error');

const generateToken = (jwks, clinetId, currentTime, expiredTime, issureUri) => {
    return jwks.token({
        "sub": clinetId,
        "auth_time": currentTime,
        "iss": issureUri,
        "exp": expiredTime,
        "iat": currentTime,
        "client_id": clinetId
    });
}

beforeAll(async () => {
    jwks.start();
});
beforeEach(async () => {
});
afterEach(async () => {
    consoleLog.mockReset();
    consoleError.mockReset();
});
afterAll(async () => {
    jwks.stop();
    consoleLog.mockRestore();
    consoleError.mockRestore();
});

describe('normaltest1', () => {
    const currentTime = Math.floor(new Date().getTime() / 1000);
    const expiredTime = currentTime + 600;

    beforeEach(async () => {
        process.env.JWKS_URI = `${issureUri}/.well-known/jwks.json`;
        process.env.TOKEN_ISSUER = issureUri;
        process.env.HTTP_PROXY = 'http://proxy.example.com'; // proxy emulate
    });

    // afterEach(async () => {
    // });

    test('[case1] under the proxy without NO_PROXY', async () => {
        const targetHandler = require('../../index').handler;
        const clinetId = "CId1";
        const token = generateToken(jwks, clinetId, currentTime, expiredTime, issureUri);
        const result = await targetHandler(token);

        expect(result).toBe("Error");
    });

    test('[case2] under the proxy with NO_PROXY', async () => {
        const targetHandler = require('../../index').handler;
        const clinetId = "CId1";
        const token = generateToken(jwks, clinetId, currentTime, expiredTime, issureUri);
        process.env.NO_PROXY += `, ${issureHost}`;

        const result = await targetHandler(token);
        expect(result).toEqual({
            "sub": clinetId,
            "auth_time": currentTime,
            "iss": process.env.TOKEN_ISSUER,
            "exp": expiredTime,
            "iat": currentTime,
            "client_id": clinetId
        });
    });
}, 10000);
