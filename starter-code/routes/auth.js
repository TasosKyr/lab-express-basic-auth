const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/user');
const router = express.Router();
const zxcvbn = require('zxcvbn');

router.get('/main', (req, res, next) => {
    if (req.session.loggedInUser) {
        res.render('auth/main');
    } else {
        res.render('error');
    }
});

router.get('/main', (req, res, next) => {
    res.render('auth/main');
});

router.get('/session', (req, res, next) => {
    res.render('auth/session');
});

router.get('/register', (req, res, next) => {
    res.render('auth/register');
});

router.get('/login', (req, res, next) => {
    res.render('auth/login');
});

router.get('/logout', (req, res, next) => {
    req.session.destroy(() => {
        res.render('auth/logout');
    });
});

router.post('/register', (req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;
    const salt = bcrypt.genSaltSync();
    const hashPassword = bcrypt.hashSync(password, salt);

    if (username === '' || password === '') {
        res.render('auth/register', {
            errorMessage: 'You need a username and a password to register'
        });
        return;
    }
    const passwordStrength = zxcvbn(password);
    if (password.length < 6) {
        res.render('auth/register', {
            errorMessage: 'Your password needs 6 or more characters'
        });
        return;
    }
    if (passwordStrength.score === 0) {
        res.render('auth/register', {
            errorMessage: passwordStrength.feedback.warning
        });
        return;
    }

    User.findOne({ username })
        .then(user => {
            if (user) {
                res.render('auth/register', {
                    errorMessage: 'There is already a registered user with this username'
                });
                return;
            }
            User.create({ username, password: hashPassword })
                .then(() => {
                    res.redirect('/main');
                })
                .catch(err => {
                    console.error('Error while registering new user', err);
                    next();
                });
        })
        .catch(err => {
            console.error('Error while looking for user', err);
        });
});

router.post('/login', (req, res, next) => {
    const { username, password } = req.body;
    if (username === '' || password === '') {
        res.render('auth/login', {
            errorMessage: 'You need a username and a password to login'
        });
        return;
    }

    User.findOne({ username })
        .then(user => {
            console.log('log success');
            if (!user) {
                res.render('auth/login', {
                    errorMessage: 'This username was not found'
                });
            }
            if (bcrypt.compareSync(password, user.password)) {
                req.session.loggedInUser = user;
                res.redirect('/main');
            } else {
                res.render('auth/login', {
                    errorMessage: 'Wrong password'
                });
            }
        })
        .catch(err => {
            console.error('Error while finding user', err);
        });
});

module.exports = router;
