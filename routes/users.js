const bcrypt = require('bcrypt')
const express = require('express');
const router = express.Router();
const User = require('../models/user')

/* GET users listing. */
router.get('/new', function(req, res, next) {
  res.render('auth-user', {
    header: 'Register a new secure user',
    action: '/users/new',
    buttonText: 'Register',
    error: false
  });
});

router.post('/new', function(req, res, next) {
  const username = req.body.username
  const password = req.body.password
  const saltRounds = 10
  
  bcrypt.hash(password, saltRounds, function(err, hash) {
    if (err) return next(err)
    const user = new User({username, hash})
    
    user.save(function(err, doc) {
      if (err) return next(err)
      res.redirect('/users/login')
    })
  })
});

router.get('/login', function(req, res, next) {
  res.render('auth-user', {
    header: 'Login a new secure user',
    action: '/users/login',
    buttonText: 'Login',
    error: false
  });
})

router.post('/login', function(req, res, next) {
  const username = req.body.username
  const password = req.body.password
  
  User.findOne({username: username}, function(err, user) {
    if (err) return next(err)
    
    const hash = user.hash
    
    bcrypt.compare(password, hash, function(err, isValid) {
      if (err) return next(err)
      
      if (!isValid) {
        res.render('auth-user', {
          header: 'Login a new secure user',
          action: '/users/login',
          buttonText: 'Login',
          error: true
        });
      }
      else res.send(`Welcome ${username}`)
    })
  })
});

module.exports = router;
