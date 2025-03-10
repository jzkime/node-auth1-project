const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

/**
  Do what needs to be done to support sessions with the `express-session` package!
  To respect users' privacy, do NOT send them a cookie unless they log in.
  This is achieved by setting 'saveUninitialized' to false, and by not
  changing the `req.session` object unless the user authenticates.

  Users that do authenticate should have a session persisted on the server,
  and a cookie set on the client. The name of the cookie should be "chocolatechip".

  The session can be persisted in memory (would not be adequate for production)
  or you can use a session store like `connect-session-knex`.
 */

const session = require('express-session');
const sessionConfig = {
  name: "chocolatechip",
  secret: "totally-secret-pw",
  cookie: {
    maxAge: 1000 * 60 * 10,
    secure: false, // not current production
    httpOnly: true
  },
  resave: false,
  saveUninitialized: false
}

const server = express();

server.use(session(sessionConfig))

server.use(helmet());
server.use(express.json());
server.use(cors());

const userRouter = require('./users/users-router');
const authRouter = require('./auth/auth-router');
server.use('/api/users', userRouter);
server.use('/api/auth', authRouter);

server.get("/", (req, res) => {
  res.json({ api: "up" });
});

server.use((err, req, res, next) => { // eslint-disable-line
  res.status(err.status || 500).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;
