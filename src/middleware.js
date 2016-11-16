const auth0 = require('./auth0');

// middleware that ensures the array of query parameter names are present in the request
exports.requireParams = (params) =>
  (req, res, next) => {
    for (var i = 0; i < params.length; i++) {
      const param = params[i];

      if (!req.query[param])
        return res.status(400).send(`Missing required parameter: ${param}`);
    }

    next();
  };

var services;
// middleware that sets a req.service object (based on the 'service' query param) which contains Auth0 information about the CAS service
exports.getService = (config) =>
  (req, res, next) => {
    auth0.getCasServices(config, (err, services) => {
      if (err)
        return next(err);

      req.service = services[req.query.service];
      if (!req.service)
        return res.status(400).send(`Unrecognized service: ${req.query.service}`);

      next();
    });
  };
