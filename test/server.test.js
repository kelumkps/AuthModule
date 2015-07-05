var request = require('supertest');
var chai = require('chai')
    , expect = chai.expect
    , should = chai.should();
var htmlparser = require("htmlparser2");
var urlParser = require('url');

var libs = process.cwd() + '/libs/';
var UserModel = require(libs + 'model/auth/user');
var ClientModel = require(libs + 'model/auth/client');
var AccessTokenModel = require(libs + 'model/auth/accessToken');
var RefreshTokenModel = require(libs + 'model/auth/refreshToken');
var GrantCodeModel = require(libs + 'model/auth/grantCode');
var log = require(libs + 'log')(module);
var config = require(libs + 'config');
require(libs + 'db/mongoose');

describe('Test Auth Server', function () {
    var url = 'http://localhost:' + config.get('port');
    log.info('Server URL :', url);
    before(function (done) {
        log.info('Refreshing database');
        UserModel.remove({}, function (err) {
            var user = new UserModel({
                username: "andrey",
                password: "simplepassword"
            });
            user.save(function (err, user) {
                if (err) return log.error(err);
                log.info("New user - %s:%s", user.username, user.password);
                ClientModel.remove({}, function (err) {
                    var client = new ClientModel({
                        name: "OurService iOS client v1",
                        clientId: "mobileV1",
                        clientSecret: "abc123456",
                        domains: "localhost"
                    });
                    client.save(function (err, client) {
                        if (err) return log.error(err);
                        log.info("New client - %s:%s", client.clientId, client.clientSecret);
                        AccessTokenModel.remove({}, function (err) {
                        });
                        RefreshTokenModel.remove({}, function (err) {
                        });
                        GrantCodeModel.remove({}, function (err) {
                        });
                        log.info('Database refreshing is completed!');
                        done();
                    });
                });
            });
        });
        done();
    });


    describe('Basic Server Health Check', function () {
        it('should return favicon.ico', function (done) {
            request(url)
                .get('/favicon.ico')
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    res.body.should.exist;
                    expect(Buffer.isBuffer(res.body)).to.be.true;
                    done();
                });
        });

        it('should return not found', function (done) {
            request(url)
                .get('/')
                .expect(404)
                .end(function (err, res) {
                    if (err) throw err;
                    res.status.should.equal(404);
                    res.body.should.exist;
                    res.body.should.have.property('error', 'Not found');
                    done();
                });
        });

        it('should return success status', function (done) {
            request(url)
                .get('/api')
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    res.status.should.equal(200);
                    res.text.should.exist;
                    res.text.should.equal('API is running');
                    done();
                });
        });
    });

    describe('Un authenticated access', function () {
        it('should return un authorized access', function (done) {
            request(url)
                .get('/api/articles')
                .expect(401)
                .end(function (err, res) {
                    if (err) throw err;
                    res.status.should.equal(401);
                    res.text.should.exist;
                    res.text.should.equal('Unauthorized');
                    done();
                });
        });
    });

    describe('OAuth 2.0 flow', function () {
        var accessToken, refreshToken, code, cookie;
        var parsedContent = {};
        var parser = new htmlparser.Parser({
            onopentag: function (name, attribs) {
                if (name === "input" && attribs.type === "hidden") {
                    parsedContent[attribs.name] = attribs.value;
                }
            }
        }, {decodeEntities: true});

        it('should return new set of access/refresh tokens from ClientPasswordStrategy', function (done) {
            var content = {
                grant_type: 'password',
                client_id: 'mobileV1',
                client_secret: 'abc123456',
                username: 'andrey',
                password: 'simplepassword'
            };
            request(url)
                .post('/oauth2/token')
                .send(content)
                .expect('Content-Type', /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    res.body.should.exist;
                    res.body.should.have.property('access_token').with.length(64);
                    res.body.should.have.property('refresh_token').with.length(64);
                    res.body.should.have.property('expires_in');
                    res.body.should.have.property('token_type', 'Bearer');

                    accessToken = res.body.access_token;
                    refreshToken = res.body.refresh_token;
                    done();
                });
        });

        it('should be able to call restricted API with a valid access token', function (done) {
            log.info('Access Token :', accessToken);
            log.info('Refresh Token:', refreshToken);
            request(url)
                .get('/api/articles')
                .set('Authorization', 'Bearer ' + accessToken)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    res.status.should.equal(200);
                    res.body.should.exist;
                    done();
                });
        });

        it('should return new set of access/refresh tokens for a valid refresh token', function (done) {
            var content = {
                grant_type: 'refresh_token',
                client_id: 'mobileV1',
                client_secret: 'abc123456',
                refresh_token: refreshToken
            };
            request(url)
                .post('/oauth2/token')
                .send(content)
                .expect('Content-Type', /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    res.body.should.exist;
                    res.body.should.have.property('access_token').with.length(64);
                    res.body.should.have.property('refresh_token').with.length(64);
                    res.body.should.have.property('expires_in');
                    res.body.should.have.property('token_type', 'Bearer');
                    done();
                });
        });

        it('should restrict API call with a old/invalid access token', function (done) {
            request(url)
                .get('/api/articles')
                .set('Authorization', 'Bearer ' + accessToken)
                .expect(401)
                .end(function (err, res) {
                    if (err) throw err;
                    res.status.should.equal(401);
                    res.text.should.exist;
                    res.text.should.equal('Unauthorized');
                    done();
                });
        });

        it('should return access grant HTML page', function (done) {
            var queryParams = {
                client_id: 'mobileV1',
                response_type: 'code',
                scope: 'edit_account,do_things',
                redirect_uri: 'http://localhost/test'
            };
            request(url)
                .get('/oauth2/auth')
                .query(queryParams)
                .set('Accept', 'test/html')
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    res.status.should.equal(200);
                    res.text.should.exist;
                    parser.write(res.text);
                    parser.end();
                    parsedContent.should.have.property('transaction_id');
                    parsedContent.should.have.property('response_type', 'code');
                    parsedContent.should.have.property('client_id', 'mobileV1');
                    cookie = res.header['set-cookie'];
                    done();
                });
        });

        it('should redirect back with grant code', function (done) {
            var postData = copyObject(parsedContent);
            postData['email'] = 'andrey';
            postData['password'] = 'simplepassword';
            log.info('POST data for grant request', postData);
            request(url)
                .post('/oauth2/decision')
                .type('form')
                .set('Cookie', cookie)
                .send(postData)
                .expect(302)
                .end(function (err, res) {
                    if (err) throw err;
                    res.status.should.equal(302);
                    res.redirect.should.true;
                    var queryParams = urlParser.parse(res.header['location'], true).query;
                    queryParams.should.have.property('code');
                    code = queryParams.code;
                    done();
                });
        });

        it('should return new set of access/refresh tokens for a valid grant code', function (done) {
            var content = {
                grant_type: 'authorization_code',
                client_id: 'mobileV1',
                client_secret: 'abc123456',
                code: code
            };
            request(url)
                .post('/oauth2/exchange')
                .send(content)
                .expect('Content-Type', /json/)
                .expect(200)
                .end(function (err, res) {
                    if (err) throw err;
                    res.body.should.exist;
                    res.body.should.have.property('access_token').with.length(64);
                    res.body.should.have.property('refresh_token').with.length(64);
                    res.body.should.have.property('expires_in');
                    res.body.should.have.property('token_type', 'Bearer');
                    done();
                });
        });

        it('should return an error for a invalid/old grant code', function (done) {
            var content = {
                grant_type: 'authorization_code',
                client_id: 'mobileV1',
                client_secret: 'abc123456',
                code: code
            };
            request(url)
                .post('/oauth2/exchange')
                .send(content)
                .expect('Content-Type', /json/)
                .expect(403)
                .end(function (err, res) {
                    if (err) throw err;
                    res.body.should.exist;
                    res.body.should.have.property('error', 'invalid_grant');
                    res.body.should.have.property('error_description', 'Invalid authorization code');
                    done();
                });
        });
    });
});

//helper function to clone a given object instance
function copyObject(obj) {
    var newObj = {};
    for (var key in obj) {
        //copy all the fields
        newObj[key] = obj[key];
    }
    return newObj;
}