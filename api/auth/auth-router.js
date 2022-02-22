const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const User = require('./../users/users-model')

router.post("/register", validateRoleName, (req, res, next) => {
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
  const { username, password } = req.body
  const { role_name } = req
  console.log(username, password, role_name)
  const hash = bcrypt.hashSync(password, 12)
  User.add({username, password: hash, role_name})
  .then(newUser => {
      console.log(username, password, role_name)
      res.status(201).json(newUser)    
    })
    .catch(next)
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
    User.findBy({username: username})
    .first()
    .then((user) => {
        if (user && bcrypt.compareSync(password, req.user.password)) {
          const token = generateToken(req.user)
          res.json({
            message: `${user.username} is back`,
            token
          })
        } else {
          res.status(401).json({message: `invalid credentials`})
        }
      })
      .catch(next)
});

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    role_name: user.role_name,
    username: user.username
  }
  const option = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, option)
}

module.exports = router;
