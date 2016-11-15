const Express = require('express');
const morgan = require('morgan');
const querystring = require('querystring');
const uuid = require('node-uuid');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const sessions = require('client-sessions');

const util = require('./util');
const middleware = require('./middleware');

module.exports = (config) => {
  const app = new Express();

  app.use(cookieParser());
  app.use(morgan('dev'));

  // configure encrypted session
  app.use(sessions({
    cookieName: 'cas-session',
    requestKey: 'session',
    secret: config('SESSION_SECRET'),
    duration: 24 * 60 * 60 * 1000,
    activeDuration: 1000 * 60 * 5
  }));

  // CAS login endpoint
  app.get('/login', middleware.requireParams(['service']), middleware.getService(config), (req, res) => {
    // generate session
    req.session.ticket = uuid.v4();
    req.session.serviceUrl = req.query.service;

    // perform OIDC Authorizaation Code Flow with Auth0
    const query = querystring.stringify({
      client_id: req.service.client_id,
      response_type: 'code',
      scope: 'openid profile',
      redirect_uri: util.buildUrl(req, '/callback'),
      connection: config('AUTH0_CONNECTION'),
      state: req.session.ticket
    });
    res.redirect(`https://${config('AUTH0_DOMAIN')}/authorize?${query}`);
  });

  // Auth0 Authorization Code Flow callback endpoint
  app.get('/callback', middleware.requireParams(['code', 'state']), (req, res) => {
    // validate session
    if (req.session.ticket !== req.query.state) return res.status(400).send(`Invalid session`);

    // store code in session
    req.session.code = req.query.code;

    res.redirect(`${req.session.serviceUrl}?ticket=${req.session.ticket}`);
  });

  // CAS validate endpoint
  app.get('/p3/serviceValidate', middleware.requireParams(['service', 'ticket']), middleware.getService(config), (req, res) => {
    // validate ticket
    if (req.session.ticket !== req.query.ticket) return res.status(400).send(`Invalid ticket`);

    // perform OAuth2 code/token exchange with Auth0
    request.post({
      url: `https://${config('AUTH0_DOMAIN')}/oauth/token`,
      json: {
        code: req.session.code,
        client_id: req.service.client_id,
        client_secret: req.service.client_secret,
        grant_type: 'authorization_code',
        redirect_uri: util.buildUrl(req, '/callback')
      }
    }, (err, response, body) => {
      if (err) throw err;
      if (response.statusCode != 200) return res.status(400).send(`IDP returned a non-successful response: ${body}`);

      //TODO: replace with RS256 verification

      // validate the id_token and return its payload in CAS format
      jwt.verify(body.id_token, new Buffer(req.service.client_secret, 'base64'), (err, payload) => {
        if (err) throw err;

        res.send(payload);
      });
    });
  });

  return app;
};
