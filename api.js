const express = require('express');
const router = express.Router();
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./db.sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            image TEXT,
            user_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER,
            user_id INTEGER,
            rate REAL,
            content TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id) REFERENCES articles(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            email TEXT,
            image TEXT
        )
    `);

});

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidPassword(password) {
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
    return passwordRegex.test(password);
}

router.post('/register', async (req, res) => {
    const { username, password, email, image } = req.body;

    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!isValidPassword(password)) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long and contain at least one letter and one number' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (row) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (row) {
                return res.status(400).json({ error: 'Email already exists' });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run(
                'INSERT INTO users (username, password, email, image) VALUES (?, ?, ?, ?)',
                [username, hashedPassword, email, image],
                function (err) {
                    if (err) {
                        return res.status(400).json({ error: err.message });
                    }
                    res.json({ id: this.lastID });
                }
            );
        });
    });
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            res.status(400).json({ error: 'Invalid username or password' });
            return;
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            res.status(400).json({ error: 'Invalid username or password' });
            return;
        }

        const token = jwt.sign({ id: user.id, username: user.username }, 'your-secret-key', { expiresIn: '1h' });

        res.json({ token:token, username: user.username, userId: user.id});
    });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

router.get('/profile', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});


router.get('/articles', (req, res) => {
    db.all('SELECT * FROM articles', (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

router.get('/articles/:id', (req, res) => {
    const articleId = req.params.id;
    db.get('SELECT * FROM articles WHERE id = ?', [articleId], (err, row) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(row);
    });
});

router.post('/articles', authenticateToken, (req, res) => {
    const { title, content, image } = req.body;
    const userId = req.user.id;

    db.run(
        'INSERT INTO articles (title, content, image, user_id) VALUES (?, ?, ?, ?)',
        [title, content, image, userId],
        function (err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ id: this.lastID });
        }
    );
});

router.put('/articles/:id', authenticateToken, (req, res) => {
    const articleId = req.params.id;
    const { title, content, image } = req.body;
    const userId = req.user.id;

    db.get('SELECT user_id FROM articles WHERE id = ?', [articleId], (err, article) => {
        if (err || !article) {
            res.status(404).json({ error: 'Article not found' });
            return;
        }

        if (article.user_id !== userId) {
            res.status(403).json({ error: 'You are not authorized to edit this article' });
            return;
        }

        db.run(
            'UPDATE articles SET title = ?, content = ?, image = ? WHERE id = ?',
            [title, content, image, articleId],
            function (err) {
                if (err) {
                    res.status(500).json({ error: err.message });
                    return;
                }
                res.json({ message: 'Article updated successfully' });
            }
        );
    });
});

router.delete('/articles/:id', authenticateToken, (req, res) => {
    const articleId = req.params.id;
    const userId = req.user.id;

    db.get('SELECT user_id FROM articles WHERE id = ?', [articleId], (err, article) => {
        if (err || !article) {
            res.status(404).json({ error: 'Article not found' });
            return;
        }

        if (article.user_id !== userId) {
            res.status(403).json({ error: 'You are not authorized to delete this article' });
            return;
        }

        db.run('DELETE FROM articles WHERE id = ?', [articleId], function (err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ message: 'Article deleted successfully' });
        });
    });
})

router.post('/articles/:id/comments', authenticateToken, (req, res) => {
    const articleId = req.params.id;
    const { rate, content } = req.body;
    const user_id = req.user.id;
    db.run('INSERT INTO comments (article_id, user_id, content, rate) VALUES (?, ?, ?, ?)', [articleId, user_id, content, rate], function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ id: this.lastID });
    });
});

router.get('/articles/:id/comments', (req, res) => {
    const articleId = req.params.id;
    db.all('SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE comments.article_id = ?;', [articleId], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

router.delete('/comments/:id', authenticateToken, (req, res) => {
    const commentId = req.params.id;
    const userId = req.user.id;

    db.get('SELECT user_id FROM comments WHERE id = ?', [commentId], (err, comment) => {
        if (err || !comment) {
            res.status(404).json({ error: 'Comment not found' });
            return;
        }

        if (comment.user_id !== userId) {
            res.status(403).json({ error: 'You are not authorized to delete this comment' });
            return;
        }

        db.run('DELETE FROM comments WHERE id = ?', [commentId], function (err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ message: 'Comment deleted successfully' });
        });
    });
});

module.exports = router;
