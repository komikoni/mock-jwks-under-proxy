'use strict';

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const createJWKSMock = require('mock-jwks').default;
const issureHost = "auth.example.com"
const issureUri = `https://${issureHost}`
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
    });

    // afterEach(async () => {
    // });

    test('not under proxy', async () => {
        const targetHandler = require('../../index').handler;
        const clinetId = "CId1";
        const token = generateToken(jwks, clinetId, currentTime, expiredTime, issureUri);
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
    test('under proxy', async () => {
        const targetHandler = require('../../index').handler;
        const clinetId = "CId1";
        const token = generateToken(jwks, clinetId, currentTime, expiredTime, issureUri);
        const result = await targetHandler(token);
        process.env.HTTP_PROXY = 'http://proxy.example.com:8080';
        process.env.HTTPS_PROXY = 'http://proxy.example.com:8080';
        process.env.http_proxy = 'http://proxy.example.com:8080';
        process.env.https_proxy = 'http://proxy.example.com:8080';
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
