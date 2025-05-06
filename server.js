const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const flash = require('connect-flash');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000; // Gunakan port dari Render
const HTML_DIR = path.join(__dirname, 'public');
const USERS_FILE = 'users.json';

// Konfigurasi Express
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'secretkey',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use(flash());

// Load & Save Users
function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    return JSON.parse(fs.readFileSync(USERS_FILE));
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Middleware untuk autentikasi
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    req.flash('error', 'Sila log masuk terlebih dahulu.');
    res.redirect('/login');
}

function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) return next();
    req.flash('error', 'Akses ditolak. Hanya admin dibenarkan.');
    res.redirect('/');
}

// Validasi Input
function validateInput(id, password) {
    const errors = [];
    if (!id || id.length < 3) errors.push('ID mestilah sekurang-kurangnya 3 aksara.');
    if (!password || password.length < 6) errors.push('Kata sandi mestilah sekurang-kurangnya 6 aksara.');
    if (!/^[a-zA-Z0-9]+$/.test(id)) errors.push('ID hanya boleh mengandungi huruf dan nombor.');
    return errors;
}

// Routes
// Beranda
app.get('/', (req, res) => {
    res.render('home', { user: req.session.user, messages: req.flash() });
});

// Halaman Registrasi
app.get('/register', (req, res) => {
    if (req.session.user) return res.redirect('/dashboard');
    res.render('register', { messages: req.flash() });
});

app.post('/register', async (req, res) => {
    const { id, password } = req.body;
    const users = loadUsers();

    // Validasi
    const errors = validateInput(id, password);
    if (errors.length > 0) {
        req.flash('error', errors.join(' '));
        return res.render('register', { messages: req.flash() });
    }

    if (users.find(u => u.id === id)) {
        req.flash('error', 'ID sudah wujud.');
        return res.render('register', { messages: req.flash() });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const expiredAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 hari
        users.push({ id, password: hashedPassword, htmls: [], expiredAt });
        saveUsers(users);
        req.flash('success', 'Pendaftaran berjaya! Sila log masuk.');
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        req.flash('error', 'Gagal mendaftar. Sila cuba lagi.');
        res.render('register', { messages: req.flash() });
    }
});

// Halaman Login
app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/dashboard');
    res.render('login', { messages: req.flash() });
});

app.post('/login', async (req, res) => {
    const { id, password } = req.body;
    const users = loadUsers();

    // Validasi
    if (!id || !password) {
        req.flash('error', 'ID dan kata sandi diperlukan.');
        return res.render('login', { messages: req.flash() });
    }

    // Cek admin
    if (id === process.env.ADMIN_ID && password === process.env.ADMIN_PASS) {
        req.session.user = { id, isAdmin: true };
        return res.redirect('/admin');
    }

    // Cek user
    const user = users.find(u => u.id === id);
    if (!user) {
        req.flash('error', 'ID tidak wujud.');
        return res.render('login', { messages: req.flash() });
    }

    try {
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.user = { id: user.id };
            res.redirect('/dashboard');
        } else {
            req.flash('error', 'Kata sandi salah.');
            res.render('login', { messages: req.flash() });
        }
    } catch (err) {
        console.error(err);
        req.flash('error', 'Gagal log masuk. Sila cuba lagi.');
        res.render('login', { messages: req.flash() });
    }
});

// Dashboard
app.get('/dashboard', isAuthenticated, (req, res) => {
    const users = loadUsers();
    const user = users.find(u => u.id === req.session.user.id);
    const now = Date.now();

    if (user.expiredAt && user.expiredAt < now) {
        req.flash('error', 'Langganan tamat. Hubungi admin.');
        return res.redirect('/logout');
    }

    res.render('dashboard', { user, messages: req.flash() });
});

// Simpan HTML
app.post('/save', isAuthenticated, (req, res) => {
    const { html } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.id === req.session.user.id);

    if (!html) {
        req.flash('error', 'Kod HTML diperlukan.');
        return res.redirect('/dashboard');
    }

    if (!user.htmls) user.htmls = [];
    if (user.htmls.length >= 5) {
        req.flash('error', 'Had maksimum 5 HTML telah dicapai.');
        return res.redirect('/dashboard');
    }

    const filename = uuidv4() + '.html';
    fs.writeFileSync(path.join(HTML_DIR, filename), html);
    user.htmls.push(filename);
    saveUsers(users);
    req.flash('success', 'HTML berjaya disimpan.');
    res.redirect('/view/' + filename);
});

// Lihat HTML
app.get('/view/:file', (req, res) => {
    const filePath = path.join(HTML_DIR, req.params.file);
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        req.flash('error', 'Fail tidak wujud.');
        res.redirect('/');
    }
});

// Edit HTML
app.get('/edit/:filename', isAuthenticated, (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(HTML_DIR, filename);
    const users = loadUsers();
    const user = users.find(u => u.id === req.session.user.id);

    if (!user.htmls.includes(filename)) {
        req.flash('error', 'Anda tidak mempunyai kebenaran untuk mengedit fail ini.');
        return res.redirect('/dashboard');
    }

    if (fs.existsSync(filePath)) {
        const htmlContent = fs.readFileSync(filePath, 'utf8');
        res.render('edit', { filename, htmlContent, messages: req.flash() });
    } else {
        req.flash('error', 'Fail tidak dijumpai.');
        res.redirect('/dashboard');
    }
});

app.post('/edit/:filename', isAuthenticated, (req, res) => {
    const filename = req.params.filename;
    const { html } = req.body;
    const filePath = path.join(HTML_DIR, filename);
    const users = loadUsers();
    const user = users.find(u => u.id === req.session.user.id);

    if (!user.htmls.includes(filename)) {
        req.flash('error', 'Anda tidak mempunyai kebenaran untuk mengedit fail ini.');
        return res.redirect('/dashboard');
    }

    if (!fs.existsSync(filePath)) {
        req.flash('error', 'Fail tidak dijumpai.');
        return res.redirect('/dashboard');
    }

    try {
        fs.writeFileSync(filePath, html);
        req.flash('success', 'Fail HTML berjaya dikemas kini.');
        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        req.flash('error', 'Gagal menyimpan perubahan.');
        res.redirect('/dashboard');
    }
});

// Hapus HTML
app.post('/delete', isAuthenticated, (req, res) => {
    const { filename } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.id === req.session.user.id);

    const index = user.htmls.indexOf(filename);
    if (index > -1) {
        user.htmls.splice(index, 1);
        const filePath = path.join(HTML_DIR, filename);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        saveUsers(users);
        req.flash('success', 'Fail HTML berjaya dipadam.');
    } else {
        req.flash('error', 'Fail tidak dijumpai.');
    }
    res.redirect('/dashboard');
});

// Halaman Admin
app.get('/admin', isAdmin, (req, res) => {
    const users = loadUsers();
    res.render('admin', { users, messages: req.flash() });
});

// Tambah Pengguna oleh Admin
app.post('/admin/add', isAdmin, async (req, res) => {
    const { id, password } = req.body;
    const users = loadUsers();

    const errors = validateInput(id, password);
    if (errors.length > 0) {
        req.flash('error', errors.join(' '));
        return res.redirect('/admin');
    }

    if (users.find(u => u.id === id)) {
        req.flash('error', 'ID pengguna telah wujud.');
        return res.redirect('/admin');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const expiredAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 hari
        users.push({ id, password: hashedPassword, htmls: [], expiredAt });
        saveUsers(users);
        req.flash('success', 'Pengguna berjaya ditambah.');
        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        req.flash('error', 'Gagal menambah pengguna.');
        res.redirect('/admin');
    }
});

// Padam Pengguna
app.post('/admin/delete', isAdmin, (req, res) => {
    const { id } = req.body;
    let users = loadUsers();
    const user = users.find(u => u.id === id);

    if (user) {
        // Padam semua fail HTML pengguna
        if (user.htmls) {
            user.htmls.forEach(filename => {
                const filePath = path.join(HTML_DIR, filename);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            });
        }
        users = users.filter(u => u.id !== id);
        saveUsers(users);
        req.flash('success', 'Pengguna berjaya dipadam.');
    } else {
        req.flash('error', 'Pengguna tidak dijumpai.');
    }
    res.redirect('/admin');
});

// Renew Pengguna
app.post('/admin/renew', isAdmin, (req, res) => {
    const { id } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.id === id);

    if (user) {
        user.expiredAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
        saveUsers(users);
        req.flash('success', `Langganan ${id} berjaya diperbaharui.`);
    } else {
        req.flash('error', 'Pengguna tidak dijumpai.');
    }
    res.redirect('/admin');
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error(err);
        req.flash('success', 'Anda telah log keluar.');
        res.redirect('/');
    });
});

// Health Check Endpoint untuk Render
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// Error 404
app.use((req, res) => {
    res.status(404).render('404', { messages: req.flash() });
});

// Jalankan server
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});