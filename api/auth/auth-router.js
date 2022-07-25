// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express');
const router = express.Router();
const { checkPasswordLength, checkUsernameExists, checkUsernameFree } = require('./auth-middleware');
const userMod = require('../users/users-model')
const bcrypt = require('bcryptjs');

router.post('/register', checkPasswordLength, checkUsernameFree, (req, res, next) => {
  const { username, password } = req.body;
  const hashPW = bcrypt.hashSync(password, 12);
  userMod.add({username, password: hashPW})
    .then(user => res.status(201).json(user))
    .catch(next);
})
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/login', checkUsernameExists, async (req, res, next) => {
  const { username, password } = req.user;
  if(!bcrypt.compareSync(req.body.password, password)) {
    next({status: 401, message: "Invalid credentials"})
    return;
    }
  req.session.user = req.user;
  res.json({message: `Welcome ${username}!`})
})
/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.get('/logout', (req, res, next) => {
  if(req.session.user) {
    req.session.destroy(err => {
      if(err) return next({message: "error in destroying cookie"})
        else return res.json({message: "logged out"})
    })
  } else {
    res.json({message: "no session"})
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
