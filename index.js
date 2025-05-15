// Import necessary modules
const express = require('express');
const path = require('path');
const session = require('express-session'); // For managing user sessions
const sqlite3 = require('sqlite3').verbose(); // Import SQLite3
const bcrypt = require('bcrypt'); // For secure password hashing

// Initialize Express app
const app = express();
// Use the PORT environment variable provided by the hosting platform, or default to 3000
const port = process.env.PORT || 3000;

// --- Database Setup (Using the provided SQLite code) ---
const db = new sqlite3.Database('./test.db', (err) => {
  if (err) {
    console.error('Error connecting to database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
    // Initialize database tables if they don't exist
    db.serialize(() => {
      // Create users table
      db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, // Store hashed passwords
        role TEXT DEFAULT 'parent'
      )`);

      // Create videos table
      db.run(`CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        thumbnail TEXT, // URL to thumbnail image
        price REAL NOT NULL,
        video_url TEXT // URL to the actual video file/stream
      )`);

      // Create a table to track video purchases (Many-to-Many relationship)
      db.run(`CREATE TABLE IF NOT EXISTS purchases (
        user_id INTEGER,
        video_id INTEGER,
        purchase_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, video_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (video_id) REFERENCES videos(id)
      )`);

      console.log("Database tables checked/created.");

      // Optional: Insert some dummy data if tables are empty
      // Check if users table is empty and insert a dummy user
      db.get("SELECT COUNT(*) AS count FROM users", (err, row) => {
        if (err) {
          console.error('Error checking users table count:', err.message);
        } else if (row.count === 0) {
          console.log("Users table is empty, inserting dummy user.");
          // Hash a dummy password before inserting
          bcrypt.hash('password123', 10, (err, hashedPassword) => {
            if (err) {
              console.error('Error hashing dummy password:', err);
            } else {
              db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ['dummy_parent', hashedPassword, 'parent'], function(err) {
                if (err) {
                  console.error('Error inserting dummy user:', err.message);
                } else {
                  console.log(`Dummy user inserted with ID: ${this.lastID}`);
                }
              });
            }
          });
        }
      });

       // Check if videos table is empty and insert dummy videos
       db.get("SELECT COUNT(*) AS count FROM videos", (err, row) => {
        if (err) {
          console.error('Error checking videos table count:', err.message);
        } else if (row.count === 0) {
          console.log("Videos table is empty, inserting dummy videos.");
          const dummyVideos = [
            { title: 'Match Highlights - Game 1', thumbnail: 'https://placehold.co/300x200?text=Video+1', price: 5.00, video_url: 'https://www.w3schools.com/html/mov_bbb.mp4' },
            { title: 'Full Match - Game 1', thumbnail: 'https://placehold.co/300x200?text=Video+2', price: 10.00, video_url: 'https://www.w3schools.com/html/mov_bbb.mp4' },
             { title: 'Training Session - Week 3', thumbnail: 'https://placehold.co/300x200?text=Video+3', price: 7.50, video_url: 'https://www.w3schools.com/html/mov_bbb.mp4' },
          ];
          const stmt = db.prepare("INSERT INTO videos (title, thumbnail, price, video_url) VALUES (?, ?, ?, ?)");
          dummyVideos.forEach(video => {
            stmt.run(video.title, video.thumbnail, video.price, video.video_url);
          });
          stmt.finalize(() => {
            console.log("Dummy videos inserted.");
          });
        }
      });
    });
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
  cookie: { secure: false } // Set to true if using HTTPS (Replit and Render provide HTTPS)
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

// --- Routes ---

// Home Page
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user }); // Pass user session data to the template
});

// Login Page
app.get('/login', (req, res) => {
  res.render('login', { error: null, message: req.query.message });
});

// Handle Login POST request
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Query the database to find the user by username
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) {
      console.error('Database error during login:', err.message);
      // Pass message as null to avoid ReferenceError
      return res.render('login', { error: 'An error occurred during login.', message: null });
    }

    if (!user) {
      // User not found
      // Pass message as null to avoid ReferenceError
      return res.render('login', { error: 'Invalid username or password.', message: null });
    }

    // Compare the submitted password with the hashed password from the database
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      // Passwords match, create a user session
      req.session.user = { id: user.id, username: user.username, role: user.role };
      res.redirect('/parent-area'); // Redirect to a protected area
    } else {
      // Passwords don't match
      // Pass message as null to avoid ReferenceError
      res.render('login', { error: 'Invalid username or password.', message: null });
    }
  });
});

// Registration Page
app.get('/register', (req, res) => {
  res.render('register', { error: null, message: req.query.message });
});

// Handle Registration POST request
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Check if the username already exists
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, existingUser) => {
    if (err) {
      console.error('Database error during registration check:', err.message);
      // Pass message as null to avoid ReferenceError
      return res.render('register', { error: 'An error occurred during registration.', message: null });
    }

    if (existingUser) {
      // Username already exists
      // Pass message as null to avoid ReferenceError
      return res.render('register', { error: 'Username already exists.', message: null });
    }

    // Securely hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store the new user's information in the database
    db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, 'parent'], function(err) {
      if (err) {
        console.error('Database error during user insertion:', err.message);
        // Pass message as null to avoid ReferenceError
        return res.render('register', { error: 'An error occurred during registration.', message: null });
      }
      console.log(`User registered with ID: ${this.lastID}`);
      res.redirect('/login?message=Registration successful! Please log in.');
    });
  });
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
app.get('/videos', (req, res) => {
    // Fetch video list from database
    db.all("SELECT * FROM videos", (err, videos) => {
        if (err) {
            console.error('Database error fetching videos:', err.message);
            return res.status(500).send("Error loading videos.");
        }
        res.render('videos', { videos: videos, user: req.session.user });
    });
});

// Video Detail/Purchase Page
app.get('/videos/:id', (req, res) => {
    const videoId = req.params.id;

    // Fetch specific video details from database
    db.get("SELECT * FROM videos WHERE id = ?", [videoId], (err, video) => {
        if (err) {
            console.error('Database error fetching video detail:', err.message);
            return res.status(500).send("Error loading video details.");
        }
        if (!video) {
            return res.status(404).send("Video not found.");
        }

        // Check if user is logged in and has purchased the video
        let hasAccess = false;
        if (req.session.user) {
            db.get("SELECT 1 FROM purchases WHERE user_id = ? AND video_id = ?", [req.session.user.id, videoId], (err, purchase) => {
                if (err) {
                    console.error('Database error checking purchase:', err.message);
                    // Continue without access if database error occurs
                } else if (purchase) {
                    hasAccess = true;
                }
                 // Render the video detail page
                res.render('video_detail', { video: video, user: req.session.user, hasAccess: hasAccess });
            });
        } else {
             // Render the video detail page for non-logged in users (no access)
            res.render('video_detail', { video: video, user: req.session.user, hasAccess: hasAccess });
        }
    });
});

// Handle Video Purchase (Placeholder - requires payment gateway integration)
app.post('/videos/:id/purchase', isAuthenticated, (req, res) => {
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

    // --- Simulate successful purchase for demo (replace with real payment logic) ---
    // For a real purchase, you'd use a payment gateway API here.
    // After successful payment, insert into the purchases table:
    db.run("INSERT OR IGNORE INTO purchases (user_id, video_id) VALUES (?, ?)", [userId, videoId], function(err) {
        if (err) {
            console.error('Database error recording purchase:', err.message);
            // Handle error, maybe redirect with an error message
            return res.redirect(`/videos/${videoId}?error=Purchase failed`);
        }
        console.log(`Simulated successful purchase recorded for user ${userId} and video ${videoId}`);
        res.redirect(`/videos/${videoId}?purchaseSuccess=true`);
    });
    // --- End Simulation ---
});


// Parent Area (Protected Route - only accessible if logged in)
app.get('/parent-area', isAuthenticated, (req, res) => {
  // User is logged in (isAuthenticated middleware handled the check)
  res.render('parent_area', { user: req.session.user });
});

// --- Add more routes for other pages (e.g., /schedule, /roster, /contact) ---

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});

// Note: Graceful database closing on server shutdown is more complex in environments like Replit.
// For development, keeping the connection open is generally fine.
// In a production environment, you'd add signal handlers (SIGINT, SIGTERM) to close the DB.
