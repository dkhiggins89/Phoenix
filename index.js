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
  ssl: { rejectUnauthorized: false },
});

// Middleware setup
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    store: new pgSession({ pool }),
    secret: process.env.SESSION_SECRET || 'your_secret_here',
    resave: false,
    saveUninitialized: false,
  })
);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login?message=Please log in');
}

function isCoach(req, res, next) {
  if (req.session.user && req.session.user.role === 'coach') return next();
  res.status(403).send('Unauthorized');
}

// Routes

// Home route
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Login routes
app.get('/login', (req, res) => {
  res.render('login', { error: null, message: req.query.message, user: req.session.user });
});

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

// Register routes
app.get('/register', (req, res) => {
  res.render('register', { error: null, message: req.query.message, user: req.session.user });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const client = await pool.connect();
  try {
    const existing = await client.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (existing.rows.length) {
      return res.render('register', { error: 'Username already exists', message: null });
    }
    const hash = await bcrypt.hash(password, 10);
    await client.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', [
      username,
      hash,
      'parent',
    ]);
    res.redirect('/login?message=Registration successful');
  } finally {
    client.release();
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Coach area home
app.get('/coach-area', isAuthenticated, isCoach, (req, res) => {
  res.render('coach_area', { user: req.session.user });
});

// Coach Area - Database Management
app.get('/coach-area/db_manage', isAuthenticated, isCoach, async (req, res) => {
  const client = await pool.connect();
  try {
    const usersResult = await client.query('SELECT * FROM users ORDER BY id');
    const videosResult = await client.query('SELECT * FROM videos ORDER BY id');

    res.render('coach-area/db_manage', {
      user: req.session.user,
      users: usersResult.rows,
      videos: videosResult.rows,
      message: req.query.message,
      error: req.query.error
    });
  } finally {
    client.release();
  }
});

//Player Profiles
app.get('/players/:id', isAuthenticated, async (req, res) => {
  const client = await pool.connect();
  try {
    const playerId = req.params.id;
    const userId = req.session.user.id;
    const role = req.session.user.role;

    const playerRes = await client.query(`SELECT * FROM players WHERE id = $1`, [playerId]);
    if (playerRes.rows.length === 0) return res.status(404).send('Player not found');

    const player = playerRes.rows[0];

    const parentsRes = await client.query(`
      SELECT u.id, u.username
      FROM player_parents pp
      JOIN users u ON u.id = pp.parent_id
      WHERE pp.player_id = $1
    `, [playerId]);

    const statsRes = await client.query(`
      SELECT * FROM player_stats WHERE player_id = $1
    `, [playerId]);

    // 🔐 Check if the current user is an assigned parent (if role is parent)
    if (role === 'parent') {
      const isParent = parentsRes.rows.some(p => p.id === userId);
      if (!isParent) return res.status(403).send('Access denied');
    }

    res.render('player_profile', {
      user: req.session.user,
      player,
      parents: parentsRes.rows,
      stats: statsRes.rows[0]
    });

  } catch (err) {
    console.error('Error loading player profile:', err);
    res.status(500).send('Something went wrong');
  } finally {
    client.release();
  }
});


  } catch (err) {
    console.error('Error loading player profile:', err);
    res.status(500).send('Something went wrong');
  } finally {
    client.release();
  }
});

app.get('/players/:id', isAuthenticated, async (req, res) => {
  const client = await pool.connect();
  try {
    const playerId = req.params.id;
    const userId = req.session.user.id;
    const role = req.session.user.role;

    const playerRes = await client.query(`SELECT * FROM players WHERE id = $1`, [playerId]);
    if (playerRes.rows.length === 0) return res.status(404).send('Player not found');

    const player = playerRes.rows[0];

    const parentsRes = await client.query(`
      SELECT u.id, u.username
      FROM player_parents pp
      JOIN users u ON u.id = pp.parent_id
      WHERE pp.player_id = $1
    `, [playerId]);

    const statsRes = await client.query(`
      SELECT * FROM player_stats WHERE player_id = $1
    `, [playerId]);

    // 🔐 Role check
    if (role === 'parent') {
      const isParent = parentsRes.rows.some(p => p.id === userId);
      if (!isParent) return res.status(403).send('Access denied');
    }

    res.render('player_profile', {
      user: req.session.user,
      player,
      parents: parentsRes.rows,
      stats: statsRes.rows[0]
    });

  } catch (err) {
    console.error('Error loading player profile:', err);
    res.status(500).send('Something went wrong');
  } finally {
    client.release();
  }
});


app.post('/players/:id/edit', isAuthenticated, isCoach, async (req, res) => {
  const { name, shirt_number, positions, parent_ids } = req.body;
  const client = await pool.connect();
  try {
    await client.query(`
      UPDATE players
      SET name = $1, shirt_number = $2, positions = $3
      WHERE id = $4
    `, [name, parseInt(shirt_number), Array.isArray(positions) ? positions : [positions], req.params.id]);

    // Clear old parents and re-add
    await client.query(`DELETE FROM player_parents WHERE player_id = $1`, [req.params.id]);

    if (parent_ids) {
      const ids = Array.isArray(parent_ids) ? parent_ids : [parent_ids];
      for (const pid of ids) {
        await client.query(`
          INSERT INTO player_parents (player_id, parent_id)
          VALUES ($1, $2) ON CONFLICT DO NOTHING
        `, [req.params.id, pid]);
      }
    }

    res.redirect(`/players/${req.params.id}?message=Profile updated`);
  } finally {
    client.release();
  }
});


// Training plan routes

// GET training plan page
app.get('/coach-area/training_plan', isAuthenticated, isCoach, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(`
      SELECT ts.id, ts.session_date, ts.location, ts.notes,
        COALESCE(
          json_agg(
            json_build_object(
              'id', td.id,
              'drill_name', td.drill_name,
              'duration_minutes', td.duration_minutes,
              'description', td.description,
              'youtube_url', td.youtube_url,
              'completed', td.completed
            )
          ) FILTER (WHERE td.id IS NOT NULL),
          '[]'
        ) AS drills
      FROM training_sessions ts
      LEFT JOIN training_drills td ON ts.id = td.session_id
      GROUP BY ts.id
      ORDER BY ts.session_date ASC
    `);

    res.render('coach-area/training_plan', {
      user: req.session.user,
      trainingSessions: result.rows,
      message: req.query.message,
      error: req.query.error,
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

app.get('/coach-area/training_plan/archive', isAuthenticated, isCoach, async (req, res) => {
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
        )) FILTER (WHERE td.id IS NOT NULL AND td.completed = TRUE), '[]') AS drills
      FROM training_sessions ts
      LEFT JOIN training_drills td ON ts.id = td.session_id
      GROUP BY ts.id
      ORDER BY ts.session_date DESC;
    `);

    // Filter out sessions with no completed drills
    const archivedSessions = result.rows.filter(
      session => Array.isArray(session.drills) && session.drills.length > 0
    );

    res.render('coach-area/training_archive', {
      user: req.session.user,
      archivedSessions
    });
  } finally {
    client.release();
  }
});

app.get('/coach-area/team_management', isAuthenticated, isCoach, async (req, res) => {
  const client = await pool.connect();
  try {
    const players = await client.query(`
      SELECT p.*, 
        COALESCE(json_agg(DISTINCT u.*) FILTER (WHERE u.id IS NOT NULL), '[]') AS parents
      FROM players p
      LEFT JOIN player_parents pp ON p.id = pp.player_id
      LEFT JOIN users u ON u.id = pp.parent_id
      GROUP BY p.id
      ORDER BY p.shirt_number ASC
    `);

    const parents = await client.query(`SELECT id, username FROM users WHERE role = 'parent' ORDER BY username`);

    res.render('coach-area/team_management', {
      user: req.session.user,
      players: players.rows,
      parents: parents.rows,
      message: req.query.message,
      error: req.query.error
    });
  } finally {
    client.release();
  }
});

app.post('/coach-area/team_management', isAuthenticated, isCoach, async (req, res) => {
  const { name, shirt_number, positions, parent_ids } = req.body;
  const client = await pool.connect();

  try {
    const result = await client.query(
      `INSERT INTO players (name, shirt_number, positions)
       VALUES ($1, $2, $3) RETURNING id`,
      [name, parseInt(shirt_number), Array.isArray(positions) ? positions : [positions]]
    );
    const playerId = result.rows[0].id;

    // Link parents
    if (parent_ids) {
      const ids = Array.isArray(parent_ids) ? parent_ids : [parent_ids];
      for (const pid of ids) {
        await client.query(
          `INSERT INTO player_parents (player_id, parent_id)
           VALUES ($1, $2) ON CONFLICT DO NOTHING`,
          [playerId, pid]
        );
      }
    }

    // Initialize player stats
    await client.query(`INSERT INTO player_stats (player_id) VALUES ($1)`, [playerId]);

    res.redirect('/coach-area/team_management?message=Player added');
  } catch (e) {
    console.error('Error adding player:', e);
    res.redirect('/coach-area/team_management?error=Error adding player');
  } finally {
    client.release();
  }
});


app.post('/coach-area/team_management/:id/delete', isAuthenticated, isCoach, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query(`DELETE FROM players WHERE id = $1`, [req.params.id]);
    res.redirect('/coach-area/team_management?message=Player removed');
  } catch (e) {
    console.error('Error deleting player:', e);
    res.redirect('/coach-area/team_management?error=Could not remove player');
  } finally {
    client.release();
  }
});



// Drill routes

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

// Edit drill form
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

// Database initialization
pool.connect((err, client, done) => {
  if (err) {
    console.error('❌ DB connection error:', err);
    process.exit(1);
  } else {
async function initializeDatabase() {
  try {
    console.log('Creating users table...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'parent'
      )
    `);

    console.log('Creating training_sessions table...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS training_sessions (
        id SERIAL PRIMARY KEY,
        session_date DATE NOT NULL,
        location TEXT,
        notes TEXT
      )
    `);

    console.log('Creating training_drills table...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS training_drills (
        id SERIAL PRIMARY KEY,
        session_id INTEGER REFERENCES training_sessions(id) ON DELETE CASCADE,
        drill_name TEXT,
        duration_minutes INTEGER,
        description TEXT,
        youtube_url TEXT
      )
    `);

    console.log('Ensuring "completed" column exists on training_drills...');
    await client.query(`
      ALTER TABLE training_drills
      ADD COLUMN IF NOT EXISTS completed BOOLEAN DEFAULT FALSE
    `);

    console.log('Creating session table...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS "session" (
        sid varchar NOT NULL,
        sess json NOT NULL,
        expire timestamp(6) NOT NULL
      )
      WITH (OIDS=FALSE)
    `);

    // After training_drills table creation
await client.query(`
  CREATE TABLE IF NOT EXISTS players (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    shirt_number INTEGER UNIQUE NOT NULL,
    positions TEXT[] DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

await client.query(`
  CREATE TABLE IF NOT EXISTS player_parents (
    player_id INTEGER REFERENCES players(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (player_id, parent_id)
  )
`);

await client.query(`
  CREATE TABLE IF NOT EXISTS player_stats (
    player_id INTEGER PRIMARY KEY REFERENCES players(id) ON DELETE CASCADE,
    goals INTEGER DEFAULT 0,
    assists INTEGER DEFAULT 0,
    minutes INTEGER DEFAULT 0,
    appearances INTEGER DEFAULT 0,
    yellow_cards INTEGER DEFAULT 0,
    red_cards INTEGER DEFAULT 0
  )
`);

    console.log('Ensuring primary key on session table...');
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'session_pkey'
        ) THEN
          ALTER TABLE "session" ADD CONSTRAINT session_pkey PRIMARY KEY (sid);
        END IF;
      END
      $$;
    `);

    console.log('Creating index on session.expire...');
    await client.query(`
      CREATE INDEX IF NOT EXISTS IDX_session_expire ON "session" (expire)
    `);

    console.log('✅ DB initialized successfully');
  } catch (e) {
    console.error('❌ DB init error:', e);
  } finally {
    done();
  }
}


    initializeDatabase();
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
