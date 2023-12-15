/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
const Users = require("../users/users-model");

async function restricted(req, res, next) {
  try {
    if (!req.session || !req.session.user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    next();
  } catch (err) {
    next(err);
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req, res, next) {
  try {
    const { username } = req.body;
    const user = await Users.findBy({ username });
    if (user.length > 0) {
      return res.status(422).json({ message: "Username is already taken" });
    }
    next();
  } catch (err) {
    next(err);
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req, res, next) {
  try {
    const { username } = req.body;
    const user = await Users.findBy({ username });
    if (user.lenth === 0) {
      return res.status(404).json({ message: "Invalid credentials" });
    }
    req.user = user[0];
    next();
  } catch (err) {
    next(err);
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req, res, next) {
  try {
    const { password } = req.body;
    if (password.length < 6) {
      return res
        .status(422)
        .json({ message: "Password should be atleast 6 characters long" });
    }
    next();
  } catch (err) {
    next(err);
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = {
  restricted,
  checkUsernameFree,
  checkPasswordLength,
  checkUsernameExists,
};
