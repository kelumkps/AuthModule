var express = require('express');
var path = require('path'); // path parsing module
var favicon = require('serve-favicon');
var morgan = require('morgan');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var log = require('./libs/log')(module);
var config = require('./libs/config');
var ArticleModel = require('./libs/mongoose').ArticleModel;
var ClientModel = require('./libs/mongoose').ClientModel;
var passport = require('passport');
var oauth2 = require('./libs/oauth2');
require('./libs/auth');
var session = require('express-session');
var url = require('url');
var app = express();


app.use(favicon(__dirname + '/public/favicon.ico')); // use standard favicon
app.set('views', __dirname + '/views');
app.set('view engine', 'jade');
app.use(morgan(config.get('logger:format'))); // log every request to the console
app.use(bodyParser.urlencoded({
    extended: false
})); // parse application/x-www-form-urlencoded  
app.use(bodyParser.json()); // parse application/json 
app.use(methodOverride()); // simulate DELETE and PUT
app.use(require('connect-flash')());
app.use(session({ secret: 'SECRET' })); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(express.static(path.join(__dirname, "public"))); // starting static fileserver, that will watch `public` folder (in our case there will be `index.html`)

app.get('/api', function (req, res) {
    res.send('API is running');
});

app.post('/oauth/token', oauth2.token);

app.get('/auth/start', oauth2.server.authorize(function (clientId, redirectURI, done) {
    ClientModel.findOne({clientId: clientId}, function (error, client) {
        if (client) {
            var match = false, uri = url.parse(redirectURI || '');
            for (var i = 0; i < client.domains.length; i++) {
                if (uri.host == client.domains[i] || (uri.protocol == client.domains[i] && uri.protocol != 'http' && uri.protocol != 'https')) {
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
});

app.post('/auth/finish', function (req, res, next) {
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
}, oauth2.server.decision(function (req, done) {
    done(null, {scope: req.oauth2.req.scope});
}));

app.post('/auth/exchange', function (req, res, next) {
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
}, oauth2.server.token(), oauth2.server.errorHandler());

app.get('/api/userInfo',
    passport.authenticate('bearer', {
        session: false
    }),
    function (req, res) {
        // req.authInfo is set using the `info` argument supplied by
        // `BearerStrategy`.  It is typically used to indicate a scope of the token,
        // and used in access control checks.  For illustrative purposes, this
        // example simply returns the scope in the response.
        res.json({
            user_id: req.user.userId,
            name: req.user.username,
            scope: req.authInfo.scope
        })
    }
);

app.get('/api/articles',
    passport.authenticate('bearer', {
        session: false
    }),
    function (req, res) {
        return ArticleModel.find(function (err, articles) {
            if (!err) {
                return res.send(articles);
            } else {
                res.statusCode = 500;
                log.error('Internal error(%d): %s', res.statusCode, err.message);
                return res.send({
                    error: 'Server error'
                });
            }
        });
    });

app.post('/api/articles', function (req, res) {
    var article = new ArticleModel({
        title: req.body.title,
        author: req.body.author,
        description: req.body.description,
        images: req.body.images
    });

    article.save(function (err) {
        if (!err) {
            log.info("article created");
            return res.send({
                status: 'OK',
                article: article
            });
        } else {
            if (err.name == 'ValidationError') {
                res.statusCode = 400;
                res.send({
                    error: 'Validation error'
                });
            } else {
                res.statusCode = 500;
                res.send({
                    error: 'Server error'
                });
            }
            log.error('Internal error(%d): %s', res.statusCode, err.message);
        }
    });
});

app.get('/api/articles/:id', function (req, res) {
    return ArticleModel.findById(req.params.id, function (err, article) {
        if (!article) {
            res.statusCode = 404;
            return res.send({
                error: 'Not found'
            });
        }
        if (!err) {
            return res.send({
                status: 'OK',
                article: article
            });
        } else {
            res.statusCode = 500;
            log.error('Internal error(%d): %s', res.statusCode, err.message);
            return res.send({
                error: 'Server error'
            });
        }
    });
});

app.put('/api/articles/:id', function (req, res) {
    return ArticleModel.findById(req.params.id, function (err, article) {
        if (!article) {
            res.statusCode = 404;
            return res.send({
                error: 'Not found'
            });
        }

        article.title = req.body.title;
        article.description = req.body.description;
        article.author = req.body.author;
        article.images = req.body.images;
        return article.save(function (err) {
            if (!err) {
                log.info("article updated");
                return res.send({
                    status: 'OK',
                    article: article
                });
            } else {
                if (err.name == 'ValidationError') {
                    res.statusCode = 400;
                    res.send({
                        error: 'Validation error'
                    });
                } else {
                    res.statusCode = 500;
                    res.send({
                        error: 'Server error'
                    });
                }
                log.error('Internal error(%d): %s', res.statusCode, err.message);
            }
        });
    });
});

app.delete('/api/articles/:id', function (req, res) {
    return ArticleModel.findById(req.params.id, function (err, article) {
        if (!article) {
            res.statusCode = 404;
            return res.send({
                error: 'Not found'
            });
        }
        return article.remove(function (err) {
            if (!err) {
                log.info("article removed");
                return res.send({
                    status: 'OK'
                });
            } else {
                res.statusCode = 500;
                log.error('Internal error(%d): %s', res.statusCode, err.message);
                return res.send({
                    error: 'Server error'
                });
            }
        });
    });
});

app.get('/ErrorExample', function (req, res, next) {
    next(new Error('Random error!'));
});

app.use(function (req, res, next) {
    res.status(404);
    log.debug('Not found URL: %s', req.url);
    res.send({
        error: 'Not found'
    });
    return;
});

app.use(function (err, req, res, next) {
    res.status(err.status || 500);
    log.error('Internal error(%d): %s ', res.statusCode, err);
    res.send({
        error: err.message
    });
    return;
});


app.listen(config.get('port'), function () {
    log.info('Express server listening on port ' + config.get('port'));
});