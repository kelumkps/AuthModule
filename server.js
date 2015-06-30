var express = require('express');
var path = require('path'); // path parsing module
var favicon = require('serve-favicon');
var morgan = require('morgan');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var log = require('./libs/log')(module);
var config = require('./libs/config');
var ArticleModel = require('./libs/model/api/article');
var passport = require('passport');
var oauth2 = require('./libs/auth/oauth2');
require('./libs/auth/auth');
require('./libs/db/mongoose');
var session = require('express-session');
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
app.use(session({secret: 'SECRET'})); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(express.static(path.join(__dirname, "public"))); // starting static file server, that will watch `public` folder (in our case there will be `index.html`)

app.get('/api', function (req, res) {
    res.send('API is running');
});

app.post('/oauth2/token', oauth2.token);

app.get('/oauth2/auth', oauth2.authorization);

app.post('/oauth2/decision', oauth2.decision);

app.post('/oauth2/exchange', oauth2.exchange);

app.get('/oauth2/revoke', oauth2.revoke);

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
});

app.use(function (err, req, res, next) {
    res.status(err.status || 500);
    log.error('Internal error(%d): ', res.statusCode, err);
    res.send({
        error: err.message
    });
});


app.listen(config.get('port'), function () {
    log.info('Express server listening on port ' + config.get('port'));
});