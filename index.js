// Import necessary modules
const express = require('express');
const path = require('path');
const session = require('express-session'); // For managing user sessions
const { Pool } = require('pg'); // Import the Pool class from pg
const bcrypt = require('bcrypt'); // For secure password hashing

// Initialize Express app
const app = express();
// Use the PORT environment variable provided by the hosting platform, or default to 3000
const port = process.env.PORT || 3000;

// --- Database Setup (Using PostgreSQL) ---
// Use the DATABASE_URL environment variable provided by Render
const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  console.error('DATABASE_URL environment variable is not set.');
  process.exit(1); // Exit if database URL is not configured
}

// Create a PostgreSQL connection pool
const pool = new Pool({
  connectionString: databaseUrl,
  ssl: {
    rejectUnauthorized: false // Required for connecting to Render's PostgreSQL from Node.js
  }
});

// Connect to the database and initialize tables
pool.connect((err, client, done) => {
  if (err) {
    console.error('Error connecting to the database:', err.message);
    // Exit the process if database connection fails
    process.exit(1);
  } else {
    console.log('Connected to the PostgreSQL database.');

    // Initialize database tables if they don't exist
    // Use async/await for cleaner table creation sequence
    async function initializeDatabase() {
      try {
        console.log('Starting database table check/creation...');

        // Create users table
        console.log('Attempting to create users table...');
        await client.query(`
          CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL, -- Store hashed passwords
            role VARCHAR(50) DEFAULT 'parent'
          );
        `);
        console.log('Users table checked/created.');

        // Create videos table
        console.log('Attempting to create videos table...');
        await client.query(`
          CREATE TABLE IF NOT EXISTS videos (
            id SERIAL PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            thumbnail VARCHAR(255), -- URL to thumbnail image
            price DECIMAL(10, 2) NOT NULL,
            video_url VARCHAR(255) -- URL to the actual video file/stream
          );
        `);
        console.log('Videos table checked/created.');

        // Create a table to track video purchases (Many-to-Many relationship)
        console.log('Attempting to create purchases table...');
        await client.query(`
          CREATE TABLE IF NOT EXISTS purchases (
            user_id INTEGER REFERENCES users(id),
            video_id INTEGER REFERENCES videos(id),
            purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, video_id)
          );
        `);
        console.log('Purchases table checked/created.');

        // Create training_sessions table
        console.log('Attempting to create training_sessions table...');
        await client.query(`
          CREATE TABLE IF NOT EXISTS training_sessions (
            id SERIAL PRIMARY KEY,
            session_date DATE NOT NULL,
            location VARCHAR(255),
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);
        console.log('training_sessions table checked/created.');

        // Create training_drills table
        console.log('Attempting to create training_drills table...');
        await client.query(`
          CREATE TABLE IF NOT EXISTS training_drills (
            id SERIAL PRIMARY KEY,
            session_id INTEGER REFERENCES training_sessions(id) ON DELETE CASCADE,
            drill_name VARCHAR(255) NOT NULL,
            duration_minutes INTEGER,
            description TEXT
          );
        `);
        console.log('training_drills table checked/created.');

        console.log("Database table check/creation sequence complete.");

        // Optional: Insert some dummy data if tables are empty
        // Check if users table is empty and insert a dummy user and a dummy coach
        const userCountResult = await client.query("SELECT COUNT(*) AS count FROM users");
        if (userCountResult.rows[0].count === '0') {
          console.log("Users table is empty, inserting dummy users.");
          // Hash dummy passwords before inserting
          const parentHashedPassword = await bcrypt.hash('password123', 10);
          await client.query("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", ['dummy_parent', parentHashedPassword, 'parent']);
          console.log('Dummy parent user inserted.');

          const coachHashedPassword = await bcrypt.hash('coachpassword', 10);
          await client.query("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", ['dummy_coach', coachHashedPassword, 'coach']);
          console.log('Dummy coach user inserted.');
        }

         // Check if videos table is empty and insert dummy videos
         const videoCountResult = await client.query("SELECT COUNT(*) AS count FROM videos");
         if (videoCountResult.rows[0].count === '0') {
           console.log("Videos table is empty, inserting dummy videos.");
           const dummyVideos = [
             { title: 'Match Highlights - Game 1', thumbnail: 'https://placehold.co/300x200?text=Video+1', price: 5.00, video_url: 'https://www.w3schools.com/html/mov_bbb.mp4' },
             { title: 'Full Match - Game 1', thumbnail: 'https://www.w3schools.com/html/mov_bbb.mp4', price: 10.00, video_url: 'https://www.w3schools.com/html/mov_bbb.mp4' },
              { title: 'Training Session - Week 3', thumbnail: 'https://placehold.co/300x200?text=Video+3', price: 7.50, video_url: 'https://www.w3schools.com/html/mov_bbb.mp4' },
           ];
           for (const video of dummyVideos) {
             await client.query("INSERT INTO videos (title, thumbnail, price, video_url) VALUES ($1, $2, $3, $4)", [video.title, video.thumbnail, video.price, video.video_url]);
           }
           console.log("Dummy videos inserted.");
         }

         // Optional: Insert dummy training sessions if tables are empty
         const sessionCountResult = await client.query("SELECT COUNT(*) AS count FROM training_sessions");
         if (sessionCountResult.rows[0].count === '0') {
            console.log("Training sessions table is empty, inserting dummy sessions.");
            const dummySessionDate1 = new Date();
            dummySessionDate1.setDate(dummySessionDate1.getDate() + 7); // 7 days from now
            const dummySession1 = await client.query("INSERT INTO training_sessions (session_date, location, notes) VALUES ($1, $2, $3) RETURNING id", [dummySessionDate1.toISOString().slice(0,10), 'Main Pitch', 'Focus on passing and movement']);
            const sessionId1 = dummySession1.rows[0].id;

            await client.query("INSERT INTO training_drills (session_id, drill_name, duration_minutes, description) VALUES ($1, $2, $3, $4)", [sessionId1, 'Warm-up', 15, 'Light jogging and stretching']);
            await client.query("INSERT INTO training_drills (session_id, drill_name, duration_minutes, description) VALUES ($1, $2, $3, $4)", [sessionId1, 'Passing Drill', 30, 'Short and long passes']);
            await client.query("INSERT INTO training_drills (session_id, drill_name, duration_minutes, description) VALUES ($1, $2, $3, $4)", [sessionId1, 'Small-sided Game', 45, 'Focus on quick decisions']);
            console.log(`Dummy training session 1 inserted with ID: ${sessionId1}`);

            const dummySessionDate2 = new Date();
            dummySessionDate2.setDate(dummySessionDate2.getDate() + 14); // 14 days from now
            const dummySession2 = await client.query("INSERT INTO training_sessions (session_date, location, notes) VALUES ($1, $2, $3) RETURNING id", [dummySessionDate2.toISOString().slice(0,10), 'Training Ground', 'Focus on shooting and defense']);
            const sessionId2 = dummySession2.rows[0].id;

            await client.query("INSERT INTO training_drills (session_id, drill_name, duration_minutes, description) VALUES ($1, $2, $3, $4)", [sessionId2, 'Shooting Practice', 25, 'Various shooting techniques']);
            await client.query("INSERT INTO training_drills (session_id, drill_name, duration_minutes, description) VALUES ($1, $2, $3, $4)", [sessionId2, 'Defensive Drills', 35, 'Positioning and tackling']);
            console.log(`Dummy training session 2 inserted with ID: ${sessionId2}`);
         }


      } catch (dbErr) {
        console.error('Database initialization error:', dbErr.message);
        // Consider exiting the process or implementing retry logic in production
      } finally {
        done(); // Release the client back to the pool
      }
    }

    initializeDatabase(); // Run the async initialization function

  }
});

// --- Middleware Setup ---

// Serve static files (CSS, images, frontend JavaScript) from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Parse URL-encoded bodies (for form data)
app.use(express.urlencoded({ extended: true }));

// Parse JSON bodies
app.use(express.json());

// Set up session management
// You'll need a strong, random secret for session security
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_default_secret_change_this', // Set this in Replit Secrets or Render Environment Variables
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS (Render provides HTTPS)
}));

// Set the view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Helper function to check if a user is logged in
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    next(); // User is authenticated, proceed to the next middleware/route handler
  } else {
    res.redirect('/login?message=Please log in to access this page'); // Redirect to login if not
  }
}

// Helper function to check if a user is a coach
function isCoach(req, res, next) {
    if (req.session.user && req.session.user.role === 'coach') {
        next(); // User is a coach, proceed
    } else {
        // Redirect or send an unauthorized message
        res.status(403).send('Unauthorized: You must be a coach to access this area.');
    }
}


// --- Routes ---

// Home Page
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user }); // Pass user session data to the template
});

// Login Page
app.get('/login', (req, res) => {
  res.render('login', { error: null, message: req.query.message, user: req.session.user }); // Pass user session data
});

// Handle Login POST request
app.post('/login', async (req, res) => { // Made async to use await
  const { username, password } = req.body;

  let client;
  try {
    client = await pool.connect(); // Get a client from the pool

    // Query the database to find the user by username
    const userResult = await client.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = userResult.rows[0]; // Get the first row

    if (!user) {
      // User not found
      return res.render('login', { error: 'Invalid username or password.', message: null, user: req.session.user });
    }

    // Compare the submitted password with the hashed password from the database
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      // Passwords match, create a user session
      req.session.user = { id: user.id, username: user.username, role: user.role };
      // Redirect based on role
      if (user.role === 'coach') {
          res.redirect('/coach-area');
      } else {
          res.redirect('/parent-area'); // Default redirect for parents
      }
    } else {
      // Passwords don't match
      res.render('login', { error: 'Invalid username or password.', message: null, user: req.session.user });
    }
  } catch (dbErr) {
    console.error('Database error during login:', dbErr.message);
    res.render('login', { error: 'An error occurred during login.', message: null, user: req.session.user });
  } finally {
    if (client) {
      client.release(); // Release the client back to the pool
    }
  }
});

// Registration Page
app.get('/register', (req, res) => {
  res.render('register', { error: null, message: req.query.message, user: req.session.user }); // Pass user session data
});

// Handle Registration POST request
app.post('/register', async (req, res) => { // Made async to use await
  const { username, password } = req.body;

  let client;
  try {
    client = await pool.connect(); // Get a client from the pool

    // Check if the username already exists
    const existingUserResult = await client.query("SELECT * FROM users WHERE username = $1", [username]);
    const existingUser = existingUserResult.rows[0];

    if (existingUser) {
      // Username already exists
      return res.render('register', { error: 'Username already exists.', message: null, user: req.session.user });
    }

    // Securely hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store the new user's information in the database
    // New users default to 'parent' role
    await client.query("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", [username, hashedPassword, 'parent']);
    console.log(`User registered: ${username}`);
    res.redirect('/login?message=Registration successful! Please log in.');

  } catch (dbErr) {
    console.error('Database error during registration:', dbErr.message);
    res.render('register', { error: 'An error occurred during registration.', message: null, user: req.session.user });
  } finally {
    if (client) {
      client.release(); // Release the client back to the pool
    }
  }
});

// Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.redirect('/'); // Redirect to home page after logout
  });
});


// Videos Page (Publicly accessible to list videos)
app.get('/videos', async (req, res) => { // Made async to use await
    let client;
    try {
        client = await pool.connect(); // Get a client from the pool
        // Fetch video list from database
        const videoResult = await client.query("SELECT * FROM videos");
        const videos = videoResult.rows;
        res.render('videos', { videos: videos, user: req.session.user });
    } catch (dbErr) {
        console.error('Database error fetching videos:', dbErr.message);
        res.status(500).send("Error loading videos.");
    } finally {
        if (client) {
            client.release(); // Release the client back to the pool
        }
    }
});

// Video Detail/Purchase Page
app.get('/videos/:id', async (req, res) => { // Made async to use await
    const videoId = req.params.id;
    let client;
    try {
        client = await pool.connect(); // Get a client from the pool

        // Fetch specific video details from database
        const videoResult = await client.query("SELECT * FROM videos WHERE id = $1", [videoId]);
        const video = videoResult.rows[0];

        if (!video) {
            return res.status(404).send("Video not found.");
        }

        // Check if user is logged in and has purchased the video
        let hasAccess = false;
        if (req.session.user) {
            const purchaseResult = await client.query("SELECT 1 FROM purchases WHERE user_id = $1 AND video_id = $2", [req.session.user.id, videoId]);
            if (purchaseResult.rows.length > 0) {
                hasAccess = true;
            }
        }
         // Render the video detail page
        res.render('video_detail', { video: video, user: req.session.user, hasAccess: hasAccess });

    } catch (dbErr) {
        console.error('Database error fetching video detail:', dbErr.message);
        res.status(500).send("Error loading video details.");
    } finally {
        if (client) {
            client.release(); // Release the client back to the pool
        }
    }
});

// Handle Video Purchase (Placeholder - requires payment gateway integration)
app.post('/videos/:id/purchase', isAuthenticated, async (req, res) => { // Made async to use await
    const videoId = req.params.id;
    const userId = req.session.user.id; // User ID is available because of isAuthenticated middleware

    // --- Placeholder Payment Processing and Access Granting ---
    // In a real application, you would:
    // 1. Integrate with a payment gateway (Stripe, PayPal, etc.) to process the payment for videoId.
    // 2. Handle successful and failed payment responses.
    // 3. If payment is successful, record the purchase in your database (link userId to videoId).
    // 4. Redirect the user to the video detail page, where the 'hasAccess' check will now pass.
    // 5. Handle errors (e.g., payment failed).

    console.log(`User ${userId} attempting to purchase video ${videoId}`);

    let client;
    try {
        client = await pool.connect(); // Get a client from the pool
        // --- Simulate successful purchase for demo (replace with real payment logic) ---
        // For a real purchase, you'd use a payment gateway API here.
        // After successful payment, insert into the purchases table:
        await client.query("INSERT INTO purchases (user_id, video_id) VALUES ($1, $2) ON CONFLICT (user_id, video_id) DO NOTHING", [userId, videoId]);
        console.log(`Simulated successful purchase recorded for user ${userId} and video ${videoId}`);
        res.redirect(`/videos/${videoId}?purchaseSuccess=true`);

    } catch (dbErr) {
        console.error('Database error recording purchase:', dbErr.message);
        // Handle error, maybe redirect with an error message
        res.redirect(`/videos/${videoId}?error=Purchase failed`);
    } finally {
        if (client) {
            client.release(); // Release the client back to the pool
        }
    }
});


// Parent Area (Protected Route - only accessible if logged in)
app.get('/parent-area', isAuthenticated, (req, res) => {
  // User is logged in (isAuthenticated middleware handled the check)
  res.render('parent_area', { user: req.session.user });
});

// Coach Area (Protected Route - only accessible if user is a coach)
app.get('/coach-area', isAuthenticated, isCoach, (req, res) => {
    // User is logged in and is a coach
    res.render('coach_area', { user: req.session.user });
});

// Database Management Page (Protected Route - only accessible if user is a coach)
app.get('/coach-area/db-manage', isAuthenticated, isCoach, async (req, res) => { // Made async to use await
    let client;
    try {
        console.log('Attempting to connect to database for db-manage page...'); // Log before connection
        client = await pool.connect(); // Get a client from the pool
        console.log('Database client connected for db-manage page.'); // Log after successful connection

        console.log('Attempting to fetch users for db-manage page...'); // Log before fetching users
        const usersResult = await client.query("SELECT id, username, role FROM users");
        const users = usersResult.rows;
        console.log(`Fetched ${users.length} users for db-manage page.`); // Log user count

        console.log('Attempting to fetch videos for db-manage page...'); // Log before fetching videos
        const videosResult = await client.query("SELECT id, title, price FROM videos");
        const videos = videosResult.rows;
        console.log(`Fetched ${videos.length} videos for db-manage page.`); // Log video count

        console.log('Rendering db_manage page...'); // Log before rendering
        // Render the database management page, passing the data
        res.render('db_manage', { user: req.session.user, users: users, videos: videos, message: req.query.message, error: req.query.error }); // Pass messages/errors
    } catch (dbErr) {
        console.error('Database error fetching data for manage page:', dbErr); // Log the full error object
        // Render with empty arrays and an error message
        res.render('db_manage', { user: req.session.user, users: [], videos: [], error: 'Error loading database data: ' + dbErr.message }); // Display error message on page
    } finally {
        if (client) {
            client.release(); // Release the client back to the pool
            console.log('Database client released for db-manage page.'); // Log after release
        }
    }
});

// Handle Update User Role POST request (Protected - Coach only)
app.post('/coach-area/users/:id/update-role', isAuthenticated, isCoach, async (req, res) => {
    const userId = req.params.id;
    const newRole = req.body.role; // Role comes from the select input

    // Validate the role to prevent unexpected values
    if (newRole !== 'parent' && newRole !== 'coach') {
        return res.redirect('/coach-area/db-manage?error=Invalid role specified.');
    }

    let client;
    try {
        client = await pool.connect();
        // Update the user's role in the database
        const result = await client.query("UPDATE users SET role = $1 WHERE id = $2", [newRole, userId]);

        if (result.rowCount > 0) {
            res.redirect('/coach-area/db-manage?message=User role updated successfully.');
        } else {
            res.redirect('/coach-area/db-manage?error=User not found.');
        }

    } catch (dbErr) {
        console.error('Database error updating user role:', dbErr.message);
        res.redirect('/coach-area/db-manage?error=An error occurred while updating role.');
    } finally {
        if (client) {
            client.release();
        }
    }
});

// Handle Delete User POST request (Protected - Coach only)
app.post('/coach-area/users/:id/delete', isAuthenticated, isCoach, async (req, res) => {
    const userId = req.params.id;

    let client;
    try {
        client = await pool.connect();

        // Before deleting the user, delete any associated purchases to avoid foreign key constraints
        await client.query("DELETE FROM purchases WHERE user_id = $1", [userId]);

        // Delete the user from the database
        const result = await client.query("DELETE FROM users WHERE id = $1", [userId]);

        if (result.rowCount > 0) {
            res.redirect('/coach-area/db-manage?message=User deleted successfully.');
        } else {
            res.redirect('/coach-area/db-manage?error=User not found.');
        }

    } catch (dbErr) {
        console.error('Database error deleting user:', dbErr.message);
        res.redirect('/coach-area/db-manage?error=An error occurred while deleting user.');
    } finally {
        if (client) {
            client.release();
        }
    }
});

// Training Planning Page (Protected Route - only accessible if user is a coach)
app.get('/coach-area/training_plan', isAuthenticated, isCoach, async (req, res) => {
    let client;
    try {
        console.log('Attempting to connect to database for training_plan page...');
        client = await pool.connect();
        console.log('Database client connected for training_plan page.');

        // Fetch training sessions and their associated drills
        const sessionsResult = await client.query(`
            SELECT
                ts.id,
                ts.session_date,
                ts.location,
                ts.notes,
                json_agg(json_build_object(
                    'id', td.id,
                    'drill_name', td.drill_name,
                    'duration_minutes', td.duration_minutes,
                    'description', td.description
                )) AS drills
            FROM training_sessions ts
            LEFT JOIN training_drills td ON ts.id = td.session_id
            GROUP BY ts.id
            ORDER BY ts.session_date DESC; -- Order by date, most recent first
        `);
        const trainingSessions = sessionsResult.rows;
        console.log(`Fetched ${trainingSessions.length} training sessions.`);

        console.log('Rendering training_plan page...');
        res.render('training_plan', {
            user: req.session.user,
            trainingSessions: trainingSessions,
            message: req.query.message,
            error: req.query.error
        });

    } catch (dbErr) {
        console.error('Database error fetching data for training_plan page:', dbErr);
        res.render('training_plan', {
            user: req.session.user,
            trainingSessions: [],
            error: 'Error loading training data: ' + dbErr.message
        });
    } finally {
        if (client) {
            client.release();
            console.log('Database client released for training_plan page.');
        }
    }
});

// --- Add more routes for other pages (e.g., /schedule, /roster, /contact) ---
// Remember to apply isAuthenticated and/or isCoach middleware as needed

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});

// Note: Graceful database closing on server shutdown is more complex in environments like Render.
// Render manages database connections for you with the Pool.
