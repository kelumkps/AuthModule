var oauth2orize = require('oauth2orize');
var passport = require('passport');
var crypto = require('crypto');
var url = require('url');
var config = require('./config');
var UserModel = require('./model/auth/user');
var ClientModel = require('./model/auth/client');
var AccessTokenModel = require('./model/auth/accessToken');
var RefreshTokenModel = require('./model/auth/refreshToken');
var GrantCodeModel = require('./model/auth/grantCode');

// create OAuth 2.0 server
var server = oauth2orize.createServer();

function issueTokens(user, client, scope, grant, done) {
    RefreshTokenModel.remove({
        userId: user.userId,
        clientId: client.clientId
    }, function (err) {
        if (err) return done(err);
        AccessTokenModel.remove({
            userId: user.userId,
            clientId: client.clientId
        }, function (err) {
            if (err) return done(err);
            var tokenValue = crypto.randomBytes(32).toString('hex');
            var refreshTokenValue = crypto.randomBytes(32).toString('hex');
            var token = new AccessTokenModel({
                token: tokenValue,
                clientId: client.clientId,
                userId: user.userId,
                scope: scope
            });
            if(grant) {
                token.grant = grant;
            }
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
}

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
        if (!scope) {
            scope = ['view_account', 'edit_account']; // should load scope based on user type
        }
        issueTokens(user, client, scope, null, done);
    });
}));

// Exchange refreshToken for an access token.
server.exchange(oauth2orize.exchange.refreshToken(function (client, refreshToken, scope, done) {
    RefreshTokenModel.findOne({
        token: refreshToken
    }, function (err, token) {
        if (err) return done(err);
        if (!token) return done(null, false);

        UserModel.findById(token.userId, function (err, user) {
            if (err) return done(err);
            if (!user) return done(null, false);

            AccessTokenModel.findOne({
                userId: user.userId,
                clientId: client.clientId
            }, function (err, token) {
                if (err) return done(err);
                if (!token) return done(null, false);

                if(!scope) {
                    scope = token.scope;
                }
                issueTokens(user, client, scope, token.grant, done);
            });
        });
    });
}));


//Obtain Grant Code
server.grant(oauth2orize.grant.code({
    scopeSeparator: [' ', ',']
}, function (client, redirectURI, user, ares, done) {
    GrantCodeModel.remove({
        client: client.clientId,
        user: user.userId
    }, function (err) {
        if (err) return done(err);
        var code = crypto.randomBytes(24).toString('hex');
        var grant = new GrantCodeModel({
            client: client.clientId,
            user: user.userId,
            scope: ares.scope,
            code: code
        });
        grant.save(function (error) {
            done(error, error ? null : grant.code);
        });
    });
}));

//Exchange grant code for an access token.
server.exchange(oauth2orize.exchange.code({
    userProperty: 'app'
}, function (client, code, redirectURI, done) {
    GrantCodeModel.findOne({code: code}, function (error, grant) {
        if (grant && grant.client == client.clientId && grant.active &&
            Math.round((Date.now() - grant.created) / 1000) < config.get('security:grantCodeLife')) {
            RefreshTokenModel.remove({
                userId: grant.user,
                clientId: client.clientId
            }, function (err) {
                if (err) return done(err);
                AccessTokenModel.remove({
                    userId: grant.user,
                    clientId: client.clientId
                }, function (err) {
                    if (err) return done(err);
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
                        if (error) return done(error);
                        grant.active = false;
                        grant.save(function (err) {
                        });
                        done(null, tokenValue, refreshTokenValue, {
                            'expires_in': config.get('security:tokenLife')
                        });
                    });
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

// user authorization endpoint
exports.authorization = [server.authorize(function (clientId, redirectURI, done) {
    ClientModel.findOne({clientId: clientId}, function (error, client) {
        if (client) {
            var match = false, uri = url.parse(redirectURI || '');
            for (var i = 0; i < client.domains.length; i++) {
                if (uri.host == client.domains[i] || (uri.protocol == client.domains[i]
                    && uri.protocol != 'http' && uri.protocol != 'https')) {
                    match = true;
                    break;
                }
            }
            if (match && redirectURI && redirectURI.length > 0) {
                done(null, client, redirectURI);
            } else {
                done(new Error("You must supply a redirect_uri that is a domain or url scheme owned by your app."), false);
            }
        } else if (!error) {
            done(new Error("There is no app with the client_id you supplied."), false);
        } else {
            done(error);
        }
    });
}), function (req, res) {
    var scopeMap = {
        // ... display strings for all scope variables ...
        view_account: 'view your account',
        edit_account: 'view and edit your account'
    };
    res.render('oauth', {
        transaction_id: req.oauth2.transactionID,
        currentURL: req.originalUrl,
        response_type: req.query.response_type,
        errors: req.flash('error'),
        scope: req.oauth2.req.scope,
        application: req.oauth2.client,
        user: req.user,
        map: scopeMap
    });
}];

// user decision endpoint
exports.decision = [function (req, res, next) {
    if (req.user) {
        next();
    } else {
        passport.authenticate('local', {
            session: false
        }, function (error, user, info) {
            if (user) {
                req.user = user;
                next();
            } else if (!error) {
                req.flash('error', 'Your email or password was incorrect. Try again.');
                res.redirect(req.body['auth_url'])
            }
        })(req, res, next);
    }
}, server.decision(function (req, done) {
    done(null, {scope: req.oauth2.req.scope});
})];

//grant code exchange end point
exports.exchange = [function (req, res, next) {
    var appID = req.body['client_id'];
    var appSecret = req.body['client_secret'];
    ClientModel.findOne({clientId: appID, clientSecret: appSecret}, function (error, client) {
        if (client) {
            req.app = client;
            next();
        } else if (!error) {
            error = new Error("There was no client with the Client ID and Secret you provided.");
            next(error);
        } else {
            next(error);
        }
    });
}, server.token(), server.errorHandler()];

// token endpoint
exports.token = [
    passport.authenticate(['basic', 'oauth2-client-password'], {
        session: false
    }),
    server.token(),
    server.errorHandler()
];
