// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require("express");
const bcrypt = require("bcrypt");
const User = require("../users/users-model");
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
} = require("./auth-middleware");
const router = express.Router();

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
  router.post(
    "/register",
    checkUsernameFree,
    checkPasswordLength,
    async (req, res, next) => {
      try {
        const { username, password } = req.body;
        const hash = bcrypt.hashSync(password, 10);
        const newUser = { username, password: hash };
        const [user] = await Users.add(newUser); // Use array destructuring to get the first element of the returned array
        if (user) {
          res.status(200).json({ user_id: user.id, username: user.username });
        } else {
          res.status(500).json({ message: "Failed to create user" });
        }
      } catch (err) {
        if (err.code === "23505") {
          // Unique constraint violation error code for PostgreSQL
          res.status(422).json({ message: "Username already taken" });
        } else if (err.message.includes("password too short")) {
          res.status(422).json({ message: "Password must be longer than 3 characters" });
        } else {
          next(err);
        }
      }
    }
  );

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
router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { password } = req.body;
    if (bcrypt.compareSync(password, req.user.password)) {
      req.session.user = req.user;
      res.status(200).json({ message: `Welcome ${req.user.username}` });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
});

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
router.get("/logout", restricted, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ message: "Unable to logout" });
    } else {
      res.status(200).json({ message: "Logged out" });
    }
  });
});

// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router;
