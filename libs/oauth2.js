var oauth2orize = require('oauth2orize');
var passport = require('passport');
var crypto = require('crypto');
var config = require('./config');
var UserModel = require('./mongoose').UserModel;
var ClientModel = require('./mongoose').ClientModel;
var AccessTokenModel = require('./mongoose').AccessTokenModel;
var RefreshTokenModel = require('./mongoose').RefreshTokenModel;
var GrantCodeModel = require('./mongoose').GrantCodeModel;

// create OAuth 2.0 server
var server = oauth2orize.createServer();

// Exchange username & password for an access token.
server.exchange(oauth2orize.exchange.password(function (client, username, password, scope, done) {
    UserModel.findOne({
        username: username
    }, function (err, user) {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(null, false);
        }
        if (!user.checkPassword(password)) {
            return done(null, false);
        }

        RefreshTokenModel.remove({
            userId: user.userId,
            clientId: client.clientId
        }, function (err) {
            if (err) return done(err);
        });
        AccessTokenModel.remove({
            userId: user.userId,
            clientId: client.clientId
        }, function (err) {
            if (err) return done(err);
        });

        var tokenValue = crypto.randomBytes(32).toString('hex');
        var refreshTokenValue = crypto.randomBytes(32).toString('hex');
        var token = new AccessTokenModel({
            token: tokenValue,
            clientId: client.clientId,
            userId: user.userId
        });
        var refreshToken = new RefreshTokenModel({
            token: refreshTokenValue,
            clientId: client.clientId,
            userId: user.userId
        });
        refreshToken.save(function (err) {
            if (err) {
                return done(err);
            }
        });
        var info = {
            scope: '*'
        };
        token.save(function (err, token) {
            if (err) {
                return done(err);
            }
            done(null, tokenValue, refreshTokenValue, {
                'expires_in': config.get('security:tokenLife')
            });
        });
    });
}));

// Exchange refreshToken for an access token.
server.exchange(oauth2orize.exchange.refreshToken(function (client, refreshToken, scope, done) {
    RefreshTokenModel.findOne({
        token: refreshToken
    }, function (err, token) {
        if (err) {
            return done(err);
        }
        if (!token) {
            return done(null, false);
        }

        UserModel.findById(token.userId, function (err, user) {
            if (err) {
                return done(err);
            }
            if (!user) {
                return done(null, false);
            }

            RefreshTokenModel.remove({
                userId: user.userId,
                clientId: client.clientId
            }, function (err) {
                if (err) return done(err);
            });
            AccessTokenModel.remove({
                userId: user.userId,
                clientId: client.clientId
            }, function (err) {
                if (err) return done(err);
            });

            var tokenValue = crypto.randomBytes(32).toString('hex');
            var refreshTokenValue = crypto.randomBytes(32).toString('hex');
            var token = new AccessTokenModel({
                token: tokenValue,
                clientId: client.clientId,
                userId: user.userId
            });
            var refreshToken = new RefreshTokenModel({
                token: refreshTokenValue,
                clientId: client.clientId,
                userId: user.userId
            });
            refreshToken.save(function (err) {
                if (err) {
                    return done(err);
                }
            });
            var info = {
                scope: '*'
            };
            token.save(function (err, token) {
                if (err) {
                    return done(err);
                }
                done(null, tokenValue, refreshTokenValue, {
                    'expires_in': config.get('security:tokenLife')
                });
            });
        });
    });
}));

server.grant(oauth2orize.grant.code({
    scopeSeparator: [' ', ',']
}, function (client, redirectURI, user, ares, done) {
    var grant = new GrantCodeModel({
        client: client.clientId,
        user: user.userId,  
        scope: ares.scope
    });
    grant.save(function (error) {
        done(error, error ? null : grant.code);
    });
}));

server.exchange(oauth2orize.exchange.code({
    userProperty: 'app'
}, function (client, code, redirectURI, done) {
    GrantCodeModel.findOne({code: code}, function (error, grant) {
        if (grant && grant.active && grant.client == client.clientId) {
            RefreshTokenModel.remove({
                userId: grant.user,
                clientId: client.clientId
            }, function (err) {
                if (err) return done(err);
            });
            AccessTokenModel.remove({
                userId: grant.user,
                clientId: client.clientId
            }, function (err) {
                if (err) return done(err);
            });

            var tokenValue = crypto.randomBytes(32).toString('hex');
            var refreshTokenValue = crypto.randomBytes(32).toString('hex');
            var refreshToken = new RefreshTokenModel({
                token: refreshTokenValue,
                clientId: client.clientId,
                userId: grant.user
            });
            refreshToken.save(function (err) {
                if (err) {
                    return done(err);
                }
            });
            var token = new AccessTokenModel({
                token: tokenValue,
                clientId: grant.client,
                userId: grant.user,
                grant: grant,
                scope: grant.scope
            });
            token.save(function (error) {
                if (error) {
                    return done(error);
                }
                done(null, tokenValue, refreshTokenValue, {
                    'expires_in': config.get('security:tokenLife')
                });
            });
        } else {
            done(error, false);
        }
    });
}));

server.serializeClient(function (client, done) {
    done(null, client.clientId);
});
server.deserializeClient(function (id, done) {
    ClientModel.findOne({
        clientId: id
    }, function (err, client) {
        done(err, err ? null : client);
    });

});


// token endpoint
module.exports.token = [
    passport.authenticate(['basic', 'oauth2-client-password'], {
        session: false
    }),
    server.token(),
    server.errorHandler()
];
module.exports.server = server;