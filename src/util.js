const url = require('url');

exports.buildUrl = (req, path) => {
  const originalUrl = url.parse(req.originalUrl || '').pathname || '';
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';

  return url.format({
    protocol: isSecure ? 'https' : 'http',
    host: req.get('host'),
    pathname: originalUrl.replace(req.path, path)
  });
}
