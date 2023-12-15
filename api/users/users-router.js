// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
const express = require('express');
const Users = require('./users-model');
const { restricted } = require('../auth/auth -middleware');
const router = express.Router();

router.get('/', restricted, async (req, res, next) => {
  try {
    const users = await Users.find();
    res.json(users.map(user => ({ user_id: user.id, username: user.username })));
  } catch (err) {
    next(err);
  }
});

module.exports = router;


/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    },
    // etc
  ]

  response on non-authenticated:
  status 401
  {
    "message": "You shall not pass!"
  }
 */



// Don't forget to add the router to the `exports` object so it can be required in other modules
