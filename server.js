const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/kolkata_fatafat8';
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_kf8_jwt_key_2026';
const DEVELOPER_ADMIN_KEY = process.env.DEVELOPER_ADMIN_KEY || 'KF8-DEV-ONLY-CHANGE-ME';

// 1. User Database Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  ptsBalance: { type: Number, default: 4500.00 },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

// 2. Bet Database Schema
const betSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true },
  baji: { type: Number, required: true, min: 1, max: 8 },
  betType: { type: String, enum: ['single', 'patti', 'jodi'], required: true },
  target: { type: String, required: true },
  stake: { type: Number, required: true, min: 1 },
  multiplier: { type: Number, default: 9 },
  potentialPayout: { type: Number, required: true },
  status: { type: String, enum: ['Pending', 'WON', 'LOST'], default: 'Pending' },
  createdAt: { type: Date, default: Date.now }
});

// 3. Result Database Schema
const resultSchema = new mongoose.Schema({
  baji: { type: Number, required: true, min: 1, max: 8 },
  patti: { type: String, required: true },
  single: { type: String, required: true },
  date: { type: String, required: true },
  declaredAt: { type: Date, default: Date.now }
});

// 4. Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, required: true },
  amount: { type: Number, required: true },
  details: { type: String },
  status: { type: String, default: 'Completed' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Bet = mongoose.model('Bet', betSchema);
const Result = mongoose.model('Result', resultSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalid or expired' });
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// --- API ROUTES ---

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Kolkata Fatafat 8 Backend Server is running!' });
});

// Register API
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email & password required' });
    }

    const existingUser = await User.findOne({ $or: [{ username: username.toLowerCase() }, { email: email.toLowerCase() }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      passwordHash,
      ptsBalance: 4500.00
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login API
app.post('/api/auth/login', async (req, res) => {
  try {
    const { identity, password, role, developerKey } = req.body;
    if (!identity || !password) {
      return res.status(400).json({ error: 'Identity & password required' });
    }

    if (role === 'admin' && developerKey !== DEVELOPER_ADMIN_KEY) {
      return res.status(403).json({ error: 'Invalid Developer Key' });
    }

    const user = await User.findOne({
      $or: [{ username: identity.toLowerCase() }, { email: identity.toLowerCase() }]
    });

    if (!user) return res.status(400).json({ error: 'Invalid identity or password' });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(400).json({ error: 'Invalid identity or password' });

    if (role === 'admin' && user.role !== 'admin') {
      user.role = 'admin';
      await user.save();
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        ptsBalance: user.ptsBalance,
        role: user.role
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Place Bet API
app.post('/api/bets/place', authenticateToken, async (req, res) => {
  try {
    const { baji, betType, target, stake } = req.body;
    if (!baji || !betType || target === undefined || !stake || stake <= 0) {
      return res.status(400).json({ error: 'Invalid bet parameters' });
    }

    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.ptsBalance < stake) {
      return res.status(400).json({ error: 'Insufficient PTS wallet balance' });
    }

    const multiplier = betType === 'single' ? 9 : 90;
    const potentialPayout = stake * multiplier;

    user.ptsBalance -= stake;
    await user.save();

    const bet = new Bet({
      userId: user._id,
      username: user.username,
      baji,
      betType,
      target: String(target),
      stake,
      multiplier,
      potentialPayout,
      status: 'Pending'
    });
    await bet.save();

    await Transaction.create({
      userId: user._id,
      type: 'Bet Placed',
      amount: -stake,
      details: `Kolkata Fatafat Baji ${baji} (${betType.toUpperCase()}: ${target})`
    });

    res.json({
      message: 'Bet placed successfully',
      newBalance: user.ptsBalance,
      bet
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin Declare Result & Payout Engine
app.post('/api/admin/declare-result', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { baji, patti, single, date } = req.body;
    if (!baji || single === undefined || !patti) {
      return res.status(400).json({ error: 'Baji, patti, and single digit required' });
    }

    const currentDate = date || new Date().toISOString().split('T')[0];

    let resultRecord = await Result.findOne({ baji, date: currentDate });
    if (resultRecord) {
      resultRecord.patti = String(patti);
      resultRecord.single = String(single);
      await resultRecord.save();
    } else {
      resultRecord = await Result.create({ baji, patti: String(patti), single: String(single), date: currentDate });
    }

    const pendingBets = await Bet.find({ baji, status: 'Pending' });
    let settledCount = 0;
    let totalWins = 0;

    for (const bet of pendingBets) {
      let isWin = false;
      if (bet.betType === 'single' && String(bet.target) === String(single)) isWin = true;
      if (bet.betType === 'patti' && String(bet.target) === String(patti)) isWin = true;

      if (isWin) {
        bet.status = 'WON';
        await bet.save();

        const user = await User.findById(bet.userId);
        if (user) {
          user.ptsBalance += bet.potentialPayout;
          await user.save();

          await Transaction.create({
            userId: user._id,
            type: 'Bet Payout (WIN)',
            amount: bet.potentialPayout,
            details: `Baji ${baji} Win Payout (${bet.betType.toUpperCase()}: ${bet.target})`
          });
        }
        totalWins++;
      } else {
        bet.status = 'LOST';
        await bet.save();
      }
      settledCount++;
    }

    res.json({
      message: `Baji ${baji} result declared and ${settledCount} bets settled!`,
      result: resultRecord,
      settledCount,
      totalWins
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start Server
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('MongoDB Database Connected');
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => console.error('MongoDB Connection Failed:', err));