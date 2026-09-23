const { Server } = require('socket.io');
require("dotenv").config();
const http = require("http");
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./db');

const app = express();

app.use(express.json());
app.use(cors());

// --- CORE ROUTES ---
app.get('/', (req, res) => {
  res.json({ status: 'success', message: 'Cocoa Backend API is live' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});



const JWT_SECRET = process.env.JWT_SECRET ;
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });


// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// --- AUTH ENDPOINTS ---

// Register User
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const queryText = `
      INSERT INTO users (name, email, phone, password_hash, role)
      VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, phone, role;
    `;
    const result = await db.query(queryText, [name, email, phone, hashedPassword, role || 'buyer']);
    const token = jwt.sign({ id: result.rows[0].id, email: result.rows[0].email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ success: true, user: result.rows[0], token });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed', details: err.message });
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'User not found' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash || '');
    if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    delete user.password_hash;
    res.json({ success: true, user, token });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

// --- CORE MARKETPLACE & BUSINESS LOGIC ---

// Get All Listings
app.get('/api/listings', async (req, res) => {
  try {
    const queryText = `
      SELECT l.*, u.name as seller_name, u.phone as seller_phone 
      FROM listings l 
      JOIN users u ON l.seller_id = u.id 
      ORDER BY l.created_at DESC;
    `;
    const result = await db.query(queryText);
    res.json({ success: true, listings: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch listings', details: err.message });
  }
});

// Create Listing (Protected)
app.post('/api/listings', authenticateToken, async (req, res) => {
  const { title, bags_available, price_per_kg } = req.body;
  try {
    const queryText = `
      INSERT INTO listings (seller_id, title, bags_available, price_per_kg)
      VALUES ($1, $2, $3, $4) RETURNING *;
    `;
    const result = await db.query(queryText, [req.user.id, title, bags_available, price_per_kg]);
    res.status(201).json({ success: true, listing: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create listing', details: err.message });
  }
});

// Create Deal/Agreement (Off-platform trade recording)
app.post('/api/deals', authenticateToken, async (req, res) => {
  const { listing_id, seller_id, agreed_price } = req.body;
  try {
    const queryText = `
      INSERT INTO deals (listing_id, buyer_id, seller_id, agreed_price, status)
      VALUES ($1, $2, $3, $4, 'pending') RETURNING *;
    `;
    const result = await db.query(queryText, [listing_id, req.user.id, seller_id, agreed_price]);
    res.status(201).json({ success: true, deal: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to record deal', details: err.message });
  }
});

// Post Buyer/Seller Rating
app.post('/api/reviews', authenticateToken, async (req, res) => {
  const { listing_id, reviewee_id, rating, comment } = req.body;
  try {
    const queryText = `
      INSERT INTO reviews (listing_id, reviewer_id, reviewee_id, rating, comment)
      VALUES ($1, $2, $3, $4, $5) RETURNING *;
    `;
    const result = await db.query(queryText, [listing_id, req.user.id, reviewee_id, rating, comment]);
    res.status(201).json({ success: true, review: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to post review', details: err.message });
  }
});

// GET Messages between users
app.get('/api/messages/:listing_id/:user1/:user2', authenticateToken, async (req, res) => {
  const { listing_id, user1, user2 } = req.params;
  try {
    const queryText = `
      SELECT * FROM messages
      WHERE listing_id = $1 AND ((sender_id = $2 AND receiver_id = $3) OR (sender_id = $3 AND receiver_id = $2))
      ORDER BY created_at ASC;
    `;
    const result = await db.query(queryText, [listing_id, user1, user2]);
    res.json({ success: true, messages: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch messages', details: err.message });
  }
});

// Initiate Call Log
app.post('/api/calls/initiate', authenticateToken, async (req, res) => {
  const { listing_id, receiver_id } = req.body;
  try {
    const queryText = `
      INSERT INTO call_logs (listing_id, caller_id, receiver_id, status)
      VALUES ($1, $2, $3, 'initiated') RETURNING *;
    `;
    const result = await db.query(queryText, [listing_id, req.user.id, receiver_id]);
    io.to(`listing_${listing_id}`).emit('incoming_call', result.rows[0]);
    res.status(201).json({ success: true, callSession: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to log call', details: err.message });
  }
});

// --- REAL-TIME WEBSOCKETS ---
io.on('connection', (socket) => {
  socket.on('join_room', (listing_id) => {
    socket.join(`listing_${listing_id}`);
  });

  socket.on('send_message', async (data) => {
    const { listing_id, sender_id, receiver_id, message_text } = data;
    try {
      const queryText = `
        INSERT INTO messages (listing_id, sender_id, receiver_id, message_text)
        VALUES ($1, $2, $3, $4) RETURNING *;
      `;
      const result = await db.query(queryText, [listing_id, sender_id, receiver_id, message_text]);
      io.to(`listing_${listing_id}`).emit('receive_message', result.rows[0]);
    } catch (err) {
      socket.emit('error_message', { error: 'Failed to send socket message' });
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Cocoa Backend running on http://localhost:${PORT}`);
});
