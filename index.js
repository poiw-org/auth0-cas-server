require('dotenv').config();
const app = require('./server.js');

const PORT = process.env.PROCESS || 3000;
app.listen(PORT, function () {
  console.log(`Example app listening on port ${PORT}.`);
});
