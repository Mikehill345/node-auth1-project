const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require('bcryptjs')
const session = require('express-session')
const sessionStore = require('connect-session-knex')(session)
const Users = require('../users/users-model')
const usersRouter = require("../users/users-router.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session({
  name: 'monkey',
  secret: 'this should come from process.env',
  cookie: {
    maxAge: 1000 * 20,
    secure: false, // production do true (https is a must)
    httpOnly: true,
  },
  resave: false,
  saveUninitialized: false,
  store: new sessionStore({
    knex: require('../database/connection'),
    tablename: 'sessions',
    sidfieldname: 'sid',
    createTable: true, 
    clearInterval: 1000 * 60 * 60,
  })
}))

server.use("/api/users", usersRouter);

server.post('/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body
    const hash = bcrypt.hashSync(password, 10)
    const user = { username, password: hash, role: 2 }
    const addedUser = await Users.add(user)
    res.status(201).json(addedUser)
  } catch {
    res.status(500).json({ message: err.message })
  }
})

server.post('/auth/login', async (req, res) => {
  try {
    const [user] = await Users.findBy({ username: req.body.username })
    if (user && bcrypt.compareSync(req.body.password, user.password)) {
      req.session.user = user
      res.status(200).json(`welcome back, ${user.username}`)
    } else {
      res.status(401).json({ message: 'bad credentials' })
    }
  } catch {
    res.status(500).json({ message: err.message })
  }
})

server.get('/auth/logout', (req, res) => {
  if (req.session && req.session.user) {
    req.session.destroy(err => {
      if (err) {
        res.json({ message: 'you cannot leave' })
      } else {
        res.json({ message: 'goodbye!' })
      }
    })
  } else {
    res.json({ message: 'no current session' })
  }
})



server.get("/", (req, res) => {
  res.json({ api: "up" });
});

module.exports = server;
