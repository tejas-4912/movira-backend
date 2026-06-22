const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')
require('dotenv').config()

const app = express()
app.use(cors())
app.use(express.json())

// ── User Schema ──
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  streak: { type: Number, default: 0 },
  recoveryProgress: { type: Number, default: 0 },
  onboardingComplete: { type: Boolean, default: false },
  profile: {
    age: Number,
    gender: String,
    height: Number,       // cm
    weight: Number,       // kg
    bmi: Number,
    bloodGroup: String,
    occupation: String,
    activityLevel: String,
    smoking: String,
    alcohol: String,
    chronicConditions: [String],
    injuryHistory: [
      {
        bodyPart: String,
        severity: String,
        year: String,
        details: String,
      }
    ],
    currentMedications: String,
    allergies: String,
    surgeryHistory: String,
    familyHistory: [String],
    emergencyContact: String,
  },
  createdAt: { type: Date, default: Date.now },
})

const User = mongoose.model('User', userSchema)

// ── Auth middleware ──
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ message: 'No token provided' })
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.userId = decoded.userId
    next()
  } catch {
    res.status(401).json({ message: 'Invalid token' })
  }
}

// ── Signup ──
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body
    const existing = await User.findOne({ email })
    if (existing) return res.status(400).json({ message: 'Email already in use' })
    const hashed = await bcrypt.hash(password, 10)
    const user = new User({ name, email, password: hashed })
    await user.save()
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, onboardingComplete: user.onboardingComplete } })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Login ──
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body
    const user = await User.findOne({ email })
    if (!user) return res.status(400).json({ message: 'Invalid email or password' })
    const match = await bcrypt.compare(password, user.password)
    if (!match) return res.status(400).json({ message: 'Invalid email or password' })
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, onboardingComplete: user.onboardingComplete } })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Save / update medical profile ──
app.put('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const { profile } = req.body
    // Calculate BMI
    if (profile.height && profile.weight) {
      const heightM = profile.height / 100
      profile.bmi = parseFloat((profile.weight / (heightM * heightM)).toFixed(1))
    }
    const user = await User.findByIdAndUpdate(
      req.userId,
      { profile, onboardingComplete: true },
      { new: true }
    )
    res.json({ user: { id: user._id, name: user.name, email: user.email, onboardingComplete: user.onboardingComplete, profile: user.profile } })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Get profile ──
app.get('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password')
    res.json({ user })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Connect & start ──
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB')
    app.listen(process.env.PORT || 5000, () =>
      console.log(`Server running on port ${process.env.PORT || 5000}`)
    )
  })
  .catch(err => console.error('MongoDB connection error:', err))
