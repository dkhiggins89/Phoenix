const express = require('express');
const path = require('path');
const session = require('express-session');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

console.log('✅ index.js started');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  store: new pgSession({ pool }),
  secret: process.env.SESSION_SECRET || 'your_secret_here',
  resave: false,
  saveUninitialized: false
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

function isAuthenticated(req, res, next) {
  if (req.session.user) next();
  else res.redirect('/login?message=Please log in');
}

function isCoach(req, res, next) {
  if (req.session.user && req.session.user.role === 'coach') next();
  else res.status(403).send('Unauthorized');
}

// Home route
app.get('/', (req, res) => res.send('Hello from Phoenix!'));

// Login form
app.get('/login', (req, res) => {
  res.render('login', { error: null, message: req.query.message, user: req.session.user });
});

// Login POST
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid credentials', message: null, user: null });
    }
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.redirect(user.role === 'coach' ? '/coach-area' : '/parent-area');
  } finally {
    client.release();
  }
});

// Register form
app.get('/register', (req, res) => {
  res.render('register', { error: null, message: req.query.message, user: req.session.user });
});

// Register POST
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const client = await pool.connect();
  try {
    const existing = await client.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (existing.rows.length) {
      return res.render('register', { error: 'Username already exists', message: null });
    }
    const hash = await bcrypt.hash(password, 10);
    await client.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
      [username, hash, 'parent']
    );
    res.redirect('/login?message=Registration successful');
  } finally {
    client.release();
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Coach Area Home
app.get('/coach-area', isAuthenticated, isCoach, (req, res) => {
  res.render('coach_area', { user: req.session.user });
});

// GET training plan page
app.get('/coach-area/training_plan', isAuthenticated, isCoach, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(`
      SELECT ts.id, ts.session_date, ts.location, ts.notes,
        COALESCE(json_agg(json_build_object(
          'id', td.id,
          'drill_name', td.drill_name,
          'duration_minutes', td.duration_minutes,
          'description', td.description,
          'youtube_url', td.youtube_url,
          'completed', td.completed
        )) FILTER (WHERE td.id IS NOT NULL), '[]') AS drills
      FROM training_sessions ts
      LEFT JOIN training_drills td ON ts.id = td.session_id
      GROUP BY ts.id
      ORDER BY ts.session_date DESC;
    `);
    res.render('coach-area/training_plan', {
      user: req.session.user,
      trainingSessions: result.rows,
      message: req.query.message,
      error: req.query.error
    });
  } finally {
    client.release();
  }
});

// POST new training session (optionally add a drill)
app.post('/coach-area/training_plan', isAuthenticated, isCoach, async (req, res) => {
  const { session_date, location, notes, youtube_url } = req.body;
  const client = await pool.connect();
  try {
    const sessionRes = await client.query(
      'INSERT INTO training_sessions (session_date, location, notes) VALUES ($1, $2, $3) RETURNING id',
      [session_date, location, notes]
    );
    const sessionId = sessionRes.rows[0].id;

    if (youtube_url && youtube_url.trim() !== '') {
      await client.query(
        'INSERT INTO training_drills (session_id, drill_name, youtube_url) VALUES ($1, $2, $3)',
        [sessionId, 'YouTube Video', youtube_url.trim()]
      );
    }

    res.redirect('/coach-area/training_plan?message=Session added');
  } finally {
    client.release();
  }
});
// Delete drill
app.post('/coach-area/drills/:id/delete', isAuthenticated, isCoach, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('DELETE FROM training_drills WHERE id = $1', [req.params.id]);
    res.redirect('/coach-area/training_plan?message=Drill deleted');
  } finally {
    client.release();
  }
});

// Mark drill as complete
app.post('/coach-area/drills/:id/complete', isAuthenticated, isCoach, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('UPDATE training_drills SET completed = TRUE WHERE id = $1', [req.params.id]);
    res.redirect('/coach-area/training_plan?message=Drill marked as complete');
  } finally {
    client.release();
  }
});

// Edit drill form page
app.get('/coach-area/drills/:id/edit', isAuthenticated, isCoach, async (req, res) => {
  const client = await pool.connect();
  try {
    const drillResult = await client.query('SELECT * FROM training_drills WHERE id = $1', [req.params.id]);
    if (drillResult.rows.length === 0) {
      return res.redirect('/coach-area/training_plan?error=Drill not found');
    }
    res.render('coach-area/edit_drill', { user: req.session.user, drill: drillResult.rows[0] });
  } finally {
    client.release();
  }
});

// Edit drill POST (update)
app.post('/coach-area/drills/:id/edit', isAuthenticated, isCoach, async (req, res) => {
  const { drill_name, duration_minutes, description, youtube_url } = req.body;
  const client = await pool.connect();
  try {
    await client.query(
      `UPDATE training_drills
       SET drill_name = $1, duration_minutes = $2, description = $3, youtube_url = $4
       WHERE id = $5`,
      [drill_name, duration_minutes || null, description || null, youtube_url || null, req.params.id]
    );
    res.redirect('/coach-area/training_plan?message=Drill updated');
  } finally {
    client.release();
  }
});
pool.connect((err, client, done) => {
  if (err) {
    console.error('❌ DB connection error:', err);
    process.exit(1);
  } else {
    async function initDb() {
      try {
        await client.query(`
          CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'parent'
          );

          CREATE TABLE IF NOT EXISTS training_sessions (
            id SERIAL PRIMARY KEY,
            session_date DATE NOT NULL,
            location TEXT,
            notes TEXT
          );

          CREATE TABLE IF NOT EXISTS training_drills (
            id SERIAL PRIMARY KEY,
            session_id INTEGER REFERENCES training_sessions(id) ON DELETE CASCADE,
            drill_name TEXT,
            duration_minutes INTEGER,
            description TEXT,
            youtube_url TEXT,
            completed BOOLEAN DEFAULT FALSE
          );
        `);
        console.log('✅ DB initialized');
      } catch (e) {
        console.error('❌ DB init error:', e);
      } finally {
        done();
      }
    }
    initDb();
  }
});
