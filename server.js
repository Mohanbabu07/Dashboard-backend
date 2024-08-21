const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect('mongodb+srv://mohanbabu:book123@cluster0.nh3orav.mongodb.net/', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Define the User schema
const UserSchema = new mongoose.Schema({
  name: String,
  password: String,
  email: { type: String, unique: true },
  count: { type: Number, default: 0 },
  gender: String,
  lastLogin: { type: Date },
});

const User = mongoose.model('User', UserSchema);

// User registration
app.post('/signup', async (req, res) => {
  const { name, password, email, gender } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, password: hashedPassword, email, gender });
    await user.save();
    res.status(201).send('User created successfully');
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).send('User Already Exist');
    }
    res.status(500).send('Server error');
  }
});

// User login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  
  if (!user) return res.status(404).send('User not found');

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).send('Invalid credentials');

  user.count += 1;
  user.lastLogin = new Date();
  await user.save();

  const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });
  res.json({ token, user });
});

// Get user profile
app.get('user/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(403).send('Token is required');
  }

  try {
    const decoded = jwt.verify(token, 'secret'); // Verify the token
    const user = await User.findById(decoded.id, { password: 0 }); // Do not return the password
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.json(user); // Send user details as response
  } catch (error) {
    res.status(401).send('Invalid token');
  }
});

app.post('admin/login', async (req, res) => {
  const { email, password } = req.body;

  // Assuming a single admin account (this could be modified for different admin handling)
  const adminEmail = 'admin@email.com'; // Define admin email
  const adminPassword = 'Admin@123'; // Define admin password (in production, consider using hashed passwords)

  if (email === adminEmail && password === adminPassword) {
      const token = jwt.sign({ role: 'admin' }, 'secret', { expiresIn: '1h' });
      return res.json({ token });
  }

  return res.status(401).send('Invalid credentials');
});

app.get('/admin/users', async (req, res) => {
  try {
      const users = await User.find({}, { password: 0 }); // Exclude the password field
      res.json(users);
  } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
