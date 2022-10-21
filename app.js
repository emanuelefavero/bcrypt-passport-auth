require('dotenv').config()

// BCRYPT - A library to help you hash passwords.
const bcrypt = require('bcryptjs')

// Express Import
const express = require('express')
const path = require('path')

// NOTE: Passport and other needed modules Import
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const session = require('express-session')

// Mongoose
const mongoose = require('mongoose')
const Schema = mongoose.Schema
const mongoDb = process.env.MONGODB_URI
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true })
const db = mongoose.connection
db.on('error', console.error.bind(console, 'mongo connection error'))
const User = mongoose.model(
  'User',
  new Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  })
)

const app = express()
app.set('views', __dirname)
app.set('view engine', 'ejs')

// NOTE: Set up the passport-local LocalStrategy
passport.use(
  new LocalStrategy((username, password, done) => {
    // query mongo database to find the user
    User.findOne({ username: username }, (err, user) => {
      if (err) {
        return done(err)
      }
      if (!user) {
        return done(null, false, { message: 'Incorrect username' })
      }

      // BCRYPT - Compare the password with the hashed password
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords math! log user in
          return done(null, user)
        } else {
          // passwords do not match!
          return done(null, false, { message: 'Incorrect password' })
        }
      })

      // TIP: All passwords previously stored in the database (without bcrypt) will no longer work
    })
  })
)

// SerializeUser - decides which data of the user object should be stored in the session (id), and attaches it to the session object:
// req.session.passport.user = {id: user.id}
passport.serializeUser((user, done) => {
  done(null, user.id)
})

// DeserializeUser - fetches the user object from the database using the id stored in the session
passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user)
  })
})

app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }))
app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))

// TIP: We can use req.locals to avoid needing to pass the 'user' object to all our views [SEE app.get('/')]
// This will make the user object available to all view templates, UNCOMMENT AND TRY! (comment out {user: req.user} in app.get('/') below)
// app.use((req, res, next) => {
//   res.locals.user = req.user
//   next()
// })

// NOTE: Auth Routes
app.get('/', (req, res) => {
  // if the user is logged in, the req.user object will be available and we can pass it to the view
  res.render('index', { user: req.user })
})
app.get('/signup', (req, res) => res.render('signup'))

app.post('/signup', (req, res, next) => {
  // BCRYPT: The second argument (10) is the length of the 'salt'
  bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
    if (err) {
      return next(err)
    }
    // create a new user and save it to the database
    const user = new User({
      username: req.body.username,
      // BCRYPT - store the hashed password in the database
      password: hashedPassword,
    }).save((err) => {
      if (err) {
        return next(err)
      }
      res.redirect('/')
    })
  })
})

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
  })
)

app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err)
    }
    res.redirect('/')
  })
})

app.listen(3000, () => console.log('app listening on port 3000!'))
