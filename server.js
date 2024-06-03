const express = require('express');
const basicAuth = require('express-basic-auth');
const app = express();
const port = 1194;

// Middleware to parse JSON bodies
app.use(express.json());

// Basic authentication middleware
app.use(basicAuth({
  users: { 'admin': 'supersecret' },
  challenge: true
}));

app.post('/', (req, res) => {
  console.log('Incoming data:', req.body);
  res.send('Data received');
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
