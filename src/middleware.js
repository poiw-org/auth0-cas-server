const auth0 = require('./auth0');

// middleware that ensures the array of query parameter names are present in the request
exports.requireParams = (params) =>
  (req, res, next) => {
    for (var i = 0; i < params.length; i++) {
      var param = params[i];

      if (!req.query[param])
        return res.status(400).send(`Missing required parameter: ${param}`);
    }

    next();
  };

var services;
// middleware that sets a req.service object (based on the 'service' query param) which contains Auth0 information about the CAS service
exports.getService = (config, cache) =>
  (req, res, next) => {
    auth0.getCasServices(config, cache, (err, services) => {
      if (err)
        return next(err);
      req.query.service = req.query.service.replace(":80",":443");
      let serviceDomain = (req.query.service.replace("http://","").replace("https://","").split("/"))[0]
      req.service = services[serviceDomain];
      if (!req.service)
        return res.status(400).send(`Unrecognized service: ${req.query.service}`);

      next();
    });
  };
