const user = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


// Sign up  a new user
exports.signUp = async (req, res) =>    {
  const { name, email, password } = req.body;

  try {
    // Check if user already exists
    const existingUser = await user.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new user({
      name,
      email,
      password: hashedPassword,
    });
    await newUser.save();

    // Generate JWT token
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(201).json({
      success: true,
      token,
    });
  } catch (error) {
    console.error('Error signing up user:', error);
    res.status(500).json({ message: 'Server error' });
  }
};


// Sign in an existing user
exports.signIn = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const existingUser = await user.findOne({ email });
    if (!existingUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, existingUser.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: existingUser._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(200).json({
      success: true,
      token,
    });
  } catch (error) {
    console.error('Error signing in user:', error);
    res.status(500).json({ message: 'Server error' });
  }
};