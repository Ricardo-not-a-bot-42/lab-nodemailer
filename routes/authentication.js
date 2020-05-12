const { Router } = require('express');
const router = new Router();

const User = require('./../models/user');
const bcryptjs = require('bcryptjs');

const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.NODEMAILER_EMAIL,
    pass: process.env.NODEMAILER_PASS,
  },
});

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.post('/sign-up', (req, res, next) => {
  const { name, email, password } = req.body;
  const characters =
    '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let token = '';
  for (let i = 0; i < 20; i++) {
    token += characters[Math.floor(Math.random() * characters.length)];
  }
  bcryptjs
    .hash(password, 10)
    .then((hash) => {
      return User.create({
        name,
        email,
        passwordHash: hash,
        status: 'Pending Confirmation',
        confirmationCode: token,
      });
    })
    .then((user) => {
      req.session.user = user._id;
      return transporter.sendMail({
        from: `Demo App <${process.env.NODEMAILER_EMAIL}>`,
        to: user.email,
        subject: 'Wish this would work email...',
        html: `<strong>Hello</strong> <a href="http://localhost:3000/validate/${token}"> Verify Email </a>`,
      });
    })
    .then((result) => {
      console.log('Email was sent successfully');
      console.log(result);
      res.redirect('/');
    })
    .catch((error) => {
      next(error);
    });
});

router.get('/validate/:token', (req, res, next) => {
  const token = req.params.token;
  User.findOneAndUpdate({ confirmationCode: token }, { status: 'Active' })
    .then(() => {
      res.redirect('/');
    })
    .catch((error) => {
      next(error);
    });
});

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const { email, password } = req.body;
  User.findOne({ email })
    .then((user) => {
      if (!user) {
        return Promise.reject(new Error("There's no user with that email."));
      } else {
        userId = user._id;
        return bcryptjs.compare(password, user.passwordHash);
      }
    })
    .then((result) => {
      if (result) {
        req.session.user = userId;
        res.redirect('/');
      } else {
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch((error) => {
      next(error);
    });
});

router.post('/sign-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

const routeGuard = require('./../middleware/route-guard');

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

module.exports = router;
