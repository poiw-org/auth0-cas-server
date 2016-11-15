const Express = require('express');
const morgan = require('morgan');
const onHeaders = require('on-headers');
const querystring = require('querystring');
const uuid = require('node-uuid');
const cookieParser = require('cookie-parser');
const request = require('request');
const jwt = require('jsonwebtoken');
const sessions = require('client-sessions');
const stringify = require('node-stringify');
const url = require('url');

function buildUrl (req, path) {
  const originalUrl = url.parse(req.originalUrl || '').pathname || '';
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';

  return url.format({
    protocol: isSecure ? 'https' : 'http',
    host: req.get('host'),
    pathname: originalUrl.replace(req.path, path)
  });
}

// middleware that ensures the array of query parameter names are present in the request
function requireParams (params) {
  return (req, res, next) => {
    for (var i = 0; i < params.length; i++) {
      const param = params[i];

      if (!req.query[param])
        return res.status(400).send(`Missing required parameter: ${param}`);
    }

    next();
  };
}

function getApiV2AccessToken (config, done) {
  request.post({
    url: `https://${config('AUTH0_DOMAIN')}/oauth/token`,
    json: {
      client_id: config('API_V2_CLIENT_ID'),
      client_secret: config('API_V2_CLIENT_SECRET'),
      audience: `https://${config('AUTH0_DOMAIN')}/api/v2/`,
      grant_type: 'client_credentials'
    }
  }, (err, response, body) => {
    if (err) return done(err);

    console.log('API v2 access token obtained.')

    return done(null, body.access_token);
  });
}

var _services;
// middleware that sets a req.service object (based on the 'service' query param) which contains Auth0 information about the CAS service
function getService (config) {
  const setService = (req, res, next) => {
    req.service = _services[req.query.service];
    if (!req.service) return res.status(400).send(`Unrecognized service: ${req.query.service}`);

    next();
  }

  return (req, res, next) => {
    if (_services) return setService(req, res, next);

    getApiV2AccessToken(config, (err, accessToken) => {
      // fetch clients from Auth0 that are configured as CAS services
      request.get({
        url: `https://${config('AUTH0_DOMAIN')}/api/v2/clients`,
        json: true,
        headers: { Authorization: `Bearer ${accessToken}` }
      }, (err, response, clients) => {
        if (err) return next(err);
        if (response.statusCode !== 200)
          return next(new Error(`Could not fetch Auth0 clients. status=${response.statusCode}, body=` + stringify(clients)));

        _services = {};
        const webApps = clients
          .filter(c => c.app_type === 'regular_web' && c.client_metadata && c.client_metadata.cas_service);
        for (var i = 0; i < webApps.length; i++) {
          const webApp = webApps[i];

          _services[webApp.client_metadata.cas_service] = {
            client_id: webApp.client_id,
            client_secret: webApp.client_secret
          }
        }

        console.log('CAS services discovered in Auth0 tenant:', _services);

        return setService(req, res, next);
      });
    });
  };
}

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
  app.get('/login', requireParams(['service']), getService(config), (req, res) => {
    // generate session
    req.session.ticket = uuid.v4();
    req.session.serviceUrl = req.query.service;

    // perform OIDC Authorizaation Code Flow with Auth0
    const query = querystring.stringify({
      client_id: req.service.client_id,
      response_type: 'code',
      scope: 'openid profile',
      redirect_uri: buildUrl(req, '/callback'),
      connection: config('AUTH0_CONNECTION'),
      state: req.session.ticket
    });
    res.redirect(`https://${config('AUTH0_DOMAIN')}/authorize?${query}`);
  });

  // Auth0 Authorization Code Flow callback endpoint
  app.get('/callback', requireParams(['code', 'state']), (req, res) => {
    // validate session
    if (req.session.ticket !== req.query.state) return res.status(400).send(`Invalid session`);

    // store code in session
    req.session.code = req.query.code;

    res.redirect(`${req.session.serviceUrl}?ticket=${req.session.ticket}`);
  });

  // CAS validate endpoint
  app.get('/p3/serviceValidate', requireParams(['service', 'ticket']), getService(config), (req, res) => {
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
        redirect_uri: buildUrl(req, '/callback')
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
