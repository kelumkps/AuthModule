var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var LocalStrategy = require('passport-local');
var config = require('./../config');
var UserModel = require('./../model/auth/user');
var ClientModel = require('./../model/auth/client');
var AccessTokenModel = require('./../model/auth/accessToken');

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, function (email, password, done) {
    UserModel.findOne({
        username: email
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
        done(null, user);
    });

}));

passport.use(new BasicStrategy(
    function (username, password, done) {
        ClientModel.findOne({
            clientId: username
        }, function (err, client) {
            if (err) {
                return done(err);
            }
            if (!client) {
                return done(null, false);
            }
            if (client.clientSecret != password) {
                return done(null, false);
            }

            return done(null, client);
        });
    }
));

passport.use(new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
        ClientModel.findOne({
            clientId: clientId
        }, function (err, client) {
            if (err) {
                return done(err);
            }
            if (!client) {
                return done(null, false);
            }
            if (client.clientSecret != clientSecret) {
                return done(null, false);
            }

            return done(null, client);
        });
    }
));

passport.use(new BearerStrategy(
    function (accessToken, done) {
        AccessTokenModel.findOne({
            token: accessToken
        }, function (err, token) {
            if (err) {
                return done(err);
            }
            if (!token) {
                return done(null, false);
            }

            if (Math.round((Date.now() - token.created) / 1000) > config.get('security:tokenLife')) {
                AccessTokenModel.remove({
                    token: accessToken
                }, function (err) {
                    if (err) return done(err);
                });
                return done(null, false, {
                    message: 'Token expired'
                });
            }

            UserModel.findById(token.userId, function (err, user) {
                if (err) {
                    return done(err);
                }
                if (!user) {
                    return done(null, false, {
                        message: 'Unknown user'
                    });
                }

                var info = {
                    scope: '*'
                };
                done(null, user, info);
            });
        });
    }
));

passport.serializeUser(function (user, done) {
    done(null, user.userId);
});
passport.deserializeUser(function (id, done) {
    UserModel.findById(id, function (error, user) {
        done(error, user);
    });
});