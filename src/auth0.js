const request = require('request');
const stringify = require('node-stringify');

var services;

exports.getCasServices = (config, done) => {
  if (services)
    return done(null, services);

  // get API V2 access_token
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

    var accessToken = body.access_token;
    console.log('API v2 access token obtained.')

    // fetch clients from Auth0 that are configured as CAS services
    request.get({
      url: `https://${config('AUTH0_DOMAIN')}/api/v2/clients`,
      json: true,
      headers: { Authorization: `Bearer ${accessToken}` }
    }, (err, response, clients) => {
      if (err) return done(err);
      if (response.statusCode !== 200)
        return done(new Error(`Could not fetch Auth0 clients. status=${response.statusCode}, body=` + stringify(clients)));

      const webApps = clients
        .filter(c => c.app_type === 'regular_web' && c.client_metadata && c.client_metadata.cas_service);

      if (webApps.length === 0)
        return done(new Error(`No clients representing CAS Services could be found in Auth0 tenant ${config('AUTH0_DOMAIN')}.`));

      services = {};
      for (var i = 0; i < webApps.length; i++) {
        const webApp = webApps[i];

        services[webApp.client_metadata.cas_service] = {
          client_id: webApp.client_id,
          client_secret: webApp.client_secret
        }
      }

      console.log(`CAS services discovered in Auth0 tenant ${config('AUTH0_DOMAIN')}:\n`,
        services);

      done(null, services);
    });
  });
};
