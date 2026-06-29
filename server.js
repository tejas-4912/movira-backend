const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cors = require('cors')
require('dotenv').config()
process.env.GROQ_API_KEY = process.env.GROQ_API_KEY || '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'

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
    age: Number, gender: String, height: Number, weight: Number, bmi: Number,
    bloodGroup: String, occupation: String, activityLevel: String,
    smoking: String, alcohol: String, chronicConditions: [String],
    injuryHistory: [{ bodyPart: String, severity: String, year: String, details: String }],
    currentMedications: String, allergies: String, surgeryHistory: String,
    familyHistory: [String], emergencyContact: String,
  },
  progress: {
    streak: { type: Number, default: 0 },
    bestStreak: { type: Number, default: 0 },
    xp: { type: Number, default: 0 },
    level: { type: Number, default: 1 },
    recoveryProgress: { type: Number, default: 0 },
    waterMl: { type: Number, default: 0 },
    lastActiveDate: { type: String, default: null },
    exercisesDoneToday: [Number],
    challengesDoneToday: [String],
    exerciseHistory: [{ date: String, completed: Boolean, count: Number }],
  },
  journal: [{
    date: String,
    painLevel: Number,
    painLocation: String,
    notes: String,
    mood: String,
    createdAt: { type: Date, default: Date.now },
  }],
  activeProtocol: {
    protocolId: String,
    startDate: String,
    currentWeek: { type: Number, default: 1 },
    completedDays: [String],
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
    if (profile.height && profile.weight) {
      const heightM = profile.height / 100
      profile.bmi = parseFloat((profile.weight / (heightM * heightM)).toFixed(1))
    }
    const user = await User.findByIdAndUpdate(req.userId, { profile, onboardingComplete: true }, { new: true })
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

// ── Get progress ──
app.get('/api/user/progress', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('progress')
    res.json({ progress: user.progress || {} })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Save progress ──
app.put('/api/user/progress', authMiddleware, async (req, res) => {
  try {
    const { progress } = req.body
    const user = await User.findByIdAndUpdate(req.userId, { progress }, { new: true })
    res.json({ progress: user.progress })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Journal: get all entries ──
app.get('/api/journal', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('journal')
    res.json({ journal: user.journal || [] })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Journal: add entry ──
app.post('/api/journal', authMiddleware, async (req, res) => {
  try {
    const { date, painLevel, painLocation, notes, mood } = req.body
    const user = await User.findById(req.userId)
    // Remove existing entry for same date
    user.journal = user.journal.filter(e => e.date !== date)
    user.journal.unshift({ date, painLevel, painLocation, notes, mood })
    await user.save()
    res.json({ journal: user.journal })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Journal: delete entry ──
app.delete('/api/journal/:date', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
    user.journal = user.journal.filter(e => e.date !== req.params.date)
    await user.save()
    res.json({ journal: user.journal })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Active protocol: get ──
app.get('/api/protocol', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('activeProtocol')
    res.json({ activeProtocol: user.activeProtocol || null })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── Active protocol: save ──
app.put('/api/protocol', authMiddleware, async (req, res) => {
  try {
    const { activeProtocol } = req.body
    const user = await User.findByIdAndUpdate(req.userId, { activeProtocol }, { new: true })
    res.json({ activeProtocol: user.activeProtocol })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// ── AI diagnosis via Groq ──
app.post('/api/ai/diagnose', authMiddleware, async (req, res) => {
  try {
    const groqKey = process.env.GROQ_API_KEY
    console.log('GROQ KEY present:', !!groqKey, groqKey ? groqKey.substring(0,8) : 'MISSING')
    const { answers, category, chiefComplaint } = req.body
    const answerText = Object.entries(answers).map(([key, val]) => `${key}: ${val}`).join('\n')
    const prompt = `You are an expert physiotherapist. A patient has completed a detailed assessment.
Category: ${category}
Chief Complaint: ${chiefComplaint || 'Not specified'}
Patient Answers:\n${answerText}
Based on this, provide:
1. A likely diagnosis or condition (2-3 sentences)
2. 4-5 specific recommended exercises with sets/reps
3. 3 diet/nutrition tips relevant to their condition
4. 3 lifestyle modifications
5. Red flags to watch for (when to see a doctor urgently)
6. Expected recovery timeline
Format your response using these exact headings:
DIAGNOSIS:\nEXERCISES:\nDIET:\nLIFESTYLE:\nRED FLAGS:\nTIMELINE:`

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}` },
      body: JSON.stringify({ model: 'llama3-8b-8192', messages: [{ role: 'user', content: prompt }], max_tokens: 1500 }),
    })
    const data = await response.json()
    const diagnosis = data.choices?.[0]?.message?.content || 'Unable to generate diagnosis.'
    res.json({ diagnosis })
  } catch (err) {
    console.error('Groq error:', err.message)
    res.status(500).json({ message: 'AI diagnosis failed', error: err.message })
  }
})


// ── AI Chat ──
app.post('/api/ai/chat', authMiddleware, async (req, res) => {
  try {
    const { message } = req.body
    const prompt = `You are a friendly expert physiotherapist assistant named MOVIRA AI. Answer the following patient question clearly and helpfully in 2-4 sentences. Be practical and specific. If the question is serious, advise seeing a professional.

Patient question: ${message}`

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}` },
      body: JSON.stringify({ model: 'llama3-8b-8192', messages: [{ role: 'user', content: prompt }], max_tokens: 300 }),
    })
    const data = await response.json()
    const reply = data.choices?.[0]?.message?.content || 'I could not answer that. Please try again.'
    res.json({ reply })
  } catch (err) {
    res.status(500).json({ message: 'Chat failed' })
  }
})

// ── Health check ──
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }))

// ── Connect & start ──
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB')
    app.listen(process.env.PORT || 5000, () => console.log(`Server running on port ${process.env.PORT || 5000}`)
    // Keep-alive ping every 14 minutes to prevent Render spin-down
    setInterval(() => {
      fetch('https://movira-backend.onrender.com/health').catch(() => {})
    }, 14 * 60 * 1000))
  })
  .catch(err => console.error('MongoDB connection error:', err))
