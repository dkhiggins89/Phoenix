// index.js

const express = require('express');
const path = require('path');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// Database setup
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL environment variable is not set.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secret_here',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware helpers
function isAuthenticated(req, res, next) {
  if (req.session.user) next();
  else res.redirect('/login?message=Please log in');
}

function isCoach(req, res, next) {
  if (req.session.user && req.session.user.role === 'coach') next();
  else res.status(403).send('Unauthorized');
}

// Database Initialization
pool.connect((err, client, done) => {
  if (err) {
    console.error('Error connecting to the database:', err.message);
    process.exit(1);
  } else {
    async function initializeDatabase() {
      try {
        console.log('Starting database initialization...');

        await client.query(`
          CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'parent'
          );
        `);

        await client.query(`
          CREATE TABLE IF NOT EXISTS videos (
            id SERIAL PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            thumbnail VARCHAR(255),
            price DECIMAL(10,2) NOT NULL,
            video_url VARCHAR(255)
          );
        `);

        await client.query(`
          CREATE TABLE IF NOT EXISTS purchases (
            user_id INTEGER REFERENCES users(id),
            video_id INTEGER REFERENCES videos(id),
            purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, video_id)
          );
        `);

        await client.query(`
          CREATE TABLE IF NOT EXISTS training_sessions (
            id SERIAL PRIMARY KEY,
            session_date DATE NOT NULL,
            location VARCHAR(255),
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);

        await client.query(`
          CREATE TABLE IF NOT EXISTS training_drills (
            id SERIAL PRIMARY KEY,
            session_id INTEGER REFERENCES training_sessions(id) ON DELETE CASCADE,
            drill_name VARCHAR(255) NOT NULL,
            duration_minutes INTEGER,
            description TEXT,
            youtube_url VARCHAR(255)
          );
        `);

        // Safe ALTER TABLE for youtube_url (if you want to add it later)
        await client.query(`
          DO $$
          BEGIN
            IF NOT EXISTS (
              SELECT 1 FROM information_schema.columns
              WHERE table_name='training_drills' AND column_name='youtube_url'
            ) THEN
              ALTER TABLE training_drills ADD COLUMN youtube_url VARCHAR(255);
            END IF;
          END;
          $$;
        `);

        console.log('Database initialization complete.');
      } catch (error) {
        console.error('Database initialization error:', error);
      } finally {
        done();
      }
    }

    initializeDatabase();
  }
});

// Routes

app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/login', (req, res) => {
  res.render('login', { error: null, message: req.query.message, user: req.session.user });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  let client;

  try {
    client = await pool.connect();
    const userResult = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = userResult.rows[0];
    if (!user) return res.render('login', { error: 'Invalid username or password.', message: null, user: null });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.render('login', { error: 'Invalid username or password.', message: null, user: null });

    req.session.user = { id: user.id, username: user.username, role: user.role };
    if (user.role === 'coach') res.redirect('/coach-area');
    else res.redirect('/parent-area');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Login error', message: null, user: null });
  } finally {
    if (client) client.release();
  }
});

app.get('/register', (req, res) => {
  res.render('register', { error: null, message: req.query.message, user: req.session.user });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  let client;

  try {
    client = await pool.connect();
    const existingUser = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) return res.render('register', { error: 'Username already exists.', message: null, user: null });

    const hashed = await bcrypt.hash(password, 10);
    await client.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', [username, hashed, 'parent']);
    res.redirect('/login?message=Registration successful! Please log in.');
  } catch (err) {
    console.error(err);
    res.render('register', { error: 'Registration error', message: null, user: null });
  } finally {
    if (client) client.release();
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/parent-area', isAuthenticated, (req, res) => {
  res.render('parent_area', { user: req.session.user });
});

app.get('/coach-area', isAuthenticated, isCoach, (req, res) => {
  res.render('coach_area', { user: req.session.user });
});

app.get('/coach-area/training_plan', isAuthenticated, isCoach, async (req, res) => {
  let client;
  try {
    client = await pool.connect();
    const sessionsResult = await client.query(`
      SELECT
        ts.id,
        ts.session_date,
        ts.location,
        ts.notes,
        COALESCE(json_agg(json_build_object(
          'id', td.id,
          'drill_name', td.drill_name,
          'duration_minutes', td.duration_minutes,
          'description', td.description,
          'youtube_url', td.youtube_url
        )) FILTER (WHERE td.id IS NOT NULL), '[]') AS drills
      FROM training_sessions ts
      LEFT JOIN training_drills td ON ts.id = td.session_id
      GROUP BY ts.id
      ORDER BY ts.session_date DESC;
    `);

    res.render('coach-area/training_plan', {
      user: req.session.user,
      trainingSessions: sessionsResult.rows,
      message: req.query.message,
      error: req.query.error
    });
  } catch (err) {
    console.error(err);
    res.render('coach-area/training_plan', {
      user: req.session.user,
      trainingSessions: [],
      error: 'Error loading training data'
    });
  } finally {
    if (client) client.release();
  }
});

app.post('/coach-area/training_plan', isAuthenticated, isCoach, async (req, res) => {
  const { session_date, location, notes, youtube_url } = req.body;
  let client;

  try {
    client = await pool.connect();

    const sessionResult = await client.query(
      `INSERT INTO training_sessions (session_date, location, notes) VALUES ($1, $2, $3) RETURNING id`,
      [session_date, location, notes]
    );
    const sessionId = sessionResult.rows[0].id;

    if (youtube_url && youtube_url.trim() !== '') {
      await client.query(
        `INSERT INTO training_drills (session_id, drill_name, youtube_url) VALUES ($1, $2, $3)`,
        [sessionId, 'YouTube Video', youtube_url.trim()]
      );
    }

    res.redirect('/coach-area/training_plan?message=Training plan added successfully');
  } catch (err) {
    console.error('Error adding training plan:', err);
    res.redirect('/coach-area/training_plan?error=Failed to add training plan');
  } finally {
    if (client) client.release();
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
