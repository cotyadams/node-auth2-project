const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const bcrypt = require('bcryptjs')
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const users = require('../users/users-model')
const jwt = require('jsonwebtoken')
const Auth = require('../users/users-model')
router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let user = req.body

  let hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS)

  user.password = hash
  req.body.role_name = req.body.role_name.trim()
  let newUser = await users.add(req.body)
   newUser = newUser[0]
  res.status(201).json(newUser)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const { username, password } = req.body
  Auth.findBy({username})
    .then(user => {
      user = user[0]
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user)
        res.status(200).json({
          message: `${username} is back!`,
          token
        })
      } else {
        res.status(401).json({
          message: "Invalid credentials"
        })
      }
    }).catch((err) => {
      next(err)
    });
});
const generateToken = (user) => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
