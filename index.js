require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/secretsApp')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('DB error:', err));

// Middleware to check login
const isAuthenticated = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    res.redirect('/login');
  }
};

// Routes
app.get('/', (req, res) => res.render('home'));

app.get('/register', (req, res) => res.render('register', { error: '' }));
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Validate
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;

  if (!emailRegex.test(email) || !passwordRegex.test(password)) {
    return res.render('register', { error: 'Invalid email or password format' });
  }

  try {
    const existing = await User.findOne({ email });
    if (existing) return res.render('register', { error: 'User already exists' });

    const user = new User({ name, email, password });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    res.render('register', { error: 'Error during registration' });
  }
});

app.get('/login', (req, res) => res.render('login', { error: '' }));
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Validate
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.render('login', { error: 'Invalid email format' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.render('login', { error: 'Incorrect email or password' });
    }

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.cookie('token', token, { httpOnly: true });
    res.redirect('/secret');
  } catch (err) {
    res.render('login', { error: 'Login failed' });
  }
});

app.get('/secret', isAuthenticated, (req, res) => {
  res.render('secret', { user: req.user });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
});