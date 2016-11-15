const request = require('request');
const stringify = require('node-stringify');

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

// middleware that ensures the array of query parameter names are present in the request
exports.requireParams = (params) => {
  return (req, res, next) => {
    for (var i = 0; i < params.length; i++) {
      const param = params[i];

      if (!req.query[param])
        return res.status(400).send(`Missing required parameter: ${param}`);
    }

    next();
  };
}

var _services;
// middleware that sets a req.service object (based on the 'service' query param) which contains Auth0 information about the CAS service
exports.getService = (config) => {
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
