// index.js with edit and archival routes

const express = require('express');
const path = require('path');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL environment variable is not set.');
  process.exit(1);
}
const pool = new Pool({ connectionString: databaseUrl, ssl: { rejectUnauthorized: false } });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET || 'secret', resave: false, saveUninitialized: false }));
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

// training_plan GET and POST omitted for brevity, assume earlier code present...

// Edit Drill - form
app.get('/coach-area/drills/:id/edit', isAuthenticated, isCoach, async (req, res) => {
  const drillId = req.params.id;
  let client;
  try {
    client = await pool.connect();
    const result = await client.query('SELECT * FROM training_drills WHERE id = $1', [drillId]);
    const drill = result.rows[0];
    res.render('coach-area/edit_drill', { user: req.session.user, drill });
  } catch (err) {
    console.error('Error loading edit form:', err);
    res.redirect('/coach-area/training_plan?error=Could not load edit form');
  } finally {
    if (client) client.release();
  }
});

// Update Drill
app.post('/coach-area/drills/:id/edit', isAuthenticated, isCoach, async (req, res) => {
  const drillId = req.params.id;
  const { drill_name, duration_minutes, description, youtube_url } = req.body;
  let client;
  try {
    client = await pool.connect();
    await client.query(
      'UPDATE training_drills SET drill_name=$1, duration_minutes=$2, description=$3, youtube_url=$4 WHERE id=$5',
      [drill_name, duration_minutes || null, description || null, youtube_url || null, drillId]
    );
    res.redirect('/coach-area/training_plan?message=Drill updated');
  } catch (err) {
    console.error('Error updating drill:', err);
    res.redirect('/coach-area/training_plan?error=Failed to update drill');
  } finally {
    if (client) client.release();
  }
});