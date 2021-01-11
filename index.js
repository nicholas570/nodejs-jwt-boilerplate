const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const connection = require('./database');

const { SERVER_PORT, CLIENT_URL, JWT_SECRET } = process.env;

const app = express();

app.use(
  cors({
    origin: CLIENT_URL,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// middleware

const authenticateWithJsonWebToken = (req, res, next) => {
  if (req.headers.authorization !== undefined) {
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err) => {
      if (err) {
        res
          .status(401)
          .json({ errorMessage: "you're not allowed to access these data" });
      } else {
        next();
      }
    });
  } else {
    res
      .status(401)
      .json({ errorMessage: "you're not allowed to access these data" });
  }
};

// Your code here!

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.json({
      error: 'Please specify an email and a password',
    });
  }

  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  req.body.password = hashedPassword;

  connection.query('INSERT INTO user SET ?', [req.body], (err, result) => {
    if (err) {
      res.status(500).json(err);
    }
    connection.query(
      'SELECT * FROM user WHERE id = ?',
      [result.insertId],
      (error, records) => {
        if (err) {
          res.status(500).json(err);
        }
        res.status(201).json({
          id: records[0].id,
          email: records[0].email,
          password: 'hidden',
        });
      }
    );
  });
});

app.post('/login', (req, res) => {
  if (!req.body.email || !req.body.password) {
    res.status(400).json({
      error: 'Please specify an email and a password',
    });
  }

  connection.query(
    'SELECT * FROM user WHERE email = ?',
    [req.body.email],
    async (err, result) => {
      if (err) {
        res.status(500).json(err);
      }

      if (result.length === 0) {
        res.status(403).json('Invalid email');
      }

      if (await bcrypt.compare(req.body.password, result[0].password)) {
        const token = jwt.sign({ id: result[0].id }, JWT_SECRET, {
          expiresIn: '1h',
        });
        return res.status(200).json({
          user: {
            id: result[0].id,
            email: result[0].email,
            password: 'hidden',
          },
          token,
        });
      }

      res.status(403).json('Invalid password');
    }
  );
});

app.get('/users', authenticateWithJsonWebToken, (req, res) => {
  connection.query('SELECT * FROM user', (err, results) => {
    if (err) {
      res.status(500).json(err);
    }

    if (results.length === 0) {
      res.status(403).json('Invalid email');
    }

    res.status(200).json(
      results.map((user) => {
        return { ...user, password: 'hidden' };
      })
    );
  });
});

// Don't write anything below this line!
app.listen(SERVER_PORT, () => {
  console.log(`Server is running on port ${SERVER_PORT}.`);
});
