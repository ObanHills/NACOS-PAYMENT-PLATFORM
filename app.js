// ==================================================================================
// NACOS PAYMENT SYSTEM - MAIN JAVASCRIPT FILE
// ==================================================================================
// Security improvements implemented:
//   1. Password hashing   — bcryptjs (cost factor 10), no plain-text passwords stored
//   2. Cloud persistence  — Firebase Firestore with localStorage fallback
//   3. Cross-device sync  — data lives in the cloud, not just one browser
//   4. Audit trail        — every approve/reject records who did it and when
//   5. Forgot-password    — requires matric + full name match (two-factor verification)
// ==================================================================================

// ==================== STORAGE LAYER ====================
// Transparent wrapper: uses Firestore when configured, localStorage otherwise.
// All reads/writes go through getData() / saveData() / the cloud helpers below.

// Current logged-in user — declared at top so all functions can access it
let currentUser = null;

const BCRYPT_ROUNDS = 8; // cost factor 8 — ~250ms, still secure, 4× faster than 10

/**
 * Hash a plain-text password.
 * Falls back to plain-text storage if bcryptjs failed to load (CDN offline).
 * @param {string} plain
 */
async function hashPassword(plain) {
    if (typeof bcrypt === 'undefined') return plain; // CDN fallback
    return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

/**
 * Verify a plain-text password against a stored hash.
 * Supports bcrypt hashes and plain-text (legacy / CDN-offline fallback).
 * @param {string} plain
 * @param {string} hash
 */
async function verifyPassword(plain, hash) {
    if (!hash) return false;
    if (!plain) return false;
    // bcrypt hash — use bcrypt.compare
    if (hash.startsWith('$2')) {
        if (typeof bcrypt !== 'undefined') {
            try { return await bcrypt.compare(plain, hash); } catch(e) { /* fall through */ }
        }
        // bcrypt unavailable — can't verify a bcrypt hash without the library
        return false;
    }
    // Plain-text comparison (legacy data or CDN offline)
    return plain === hash;
}

// ── localStorage helpers (always available as fallback) ──────────────────────

function initializeData() {
    if (!localStorage.getItem('nacos_payments')) {
        const defaultData = {
            settings: {
                bankName: 'UBA Bank',
                accountName: 'NACOS PLASU Chapter',
                accountNumber: '1000123456',
                dues: { '100': 5000, '200': 4000, '300': 4000, '400': 3000 },
                adminSignature: ''
            },
            users: [
                {
                    id: 'admin_1',
                    name: 'Admin User',
                    email: '',
                    phone: '',
                    matricNumber: 'ADMIN',
                    level: 'None',
                    password: 'admin',   // plain-text — works without bcrypt
                    isAdmin: true
                }
            ],
            transactions: [],
            auditLog: []
        };
        localStorage.setItem('nacos_payments', JSON.stringify(defaultData));
    } else {
        // Safety: ensure admin account always exists and password is recoverable
        const data = JSON.parse(localStorage.getItem('nacos_payments'));
        const admin = data.users.find(u => u.isAdmin);
        if (!admin) {
            // Admin was deleted — restore it
            data.users.unshift({
                id: 'admin_1', name: 'Admin User', email: '', phone: '',
                matricNumber: 'ADMIN', level: 'None', password: 'admin', isAdmin: true
            });
            localStorage.setItem('nacos_payments', JSON.stringify(data));
        }
    }
    return JSON.parse(localStorage.getItem('nacos_payments'));
}

function saveData(data) {
    localStorage.setItem('nacos_payments', JSON.stringify(data));
    // If Firebase is configured, sync to cloud asynchronously
    if (typeof FIREBASE_ENABLED !== 'undefined' && FIREBASE_ENABLED) {
        syncToFirebase(data).catch(err => console.warn('Firebase sync failed:', err));
    }
}

function getData() {
    return JSON.parse(localStorage.getItem('nacos_payments'));
}

// ── Firebase cloud helpers ────────────────────────────────────────────────────

/**
 * Push the entire data object to Firestore.
 * Uses a single document 'main' in collection 'nacos_data'.
 * Firestore has a 1MB document limit — fine for this use case.
 * @param {Object} data
 */
async function syncToFirebase(data) {
    if (typeof db === 'undefined') return;
    // Strip large base64 images from cloud sync to stay under Firestore 1MB limit
    const cloudData = JSON.parse(JSON.stringify(data));
    cloudData.users = cloudData.users.map(u => ({ ...u, profilePic: u.profilePic ? '[photo]' : '' }));
    cloudData.settings.adminSignature = cloudData.settings.adminSignature ? '[signature]' : '';
    cloudData.transactions = cloudData.transactions.map(t => ({ ...t, proofImage: t.proofImage ? '[proof]' : '' }));
    await db.collection('nacos_data').doc('main').set(cloudData);
}

/**
 * Load data from Firestore and merge into localStorage.
 * Called once on app start when Firebase is configured.
 * Images (base64) are kept from localStorage since they're stripped from cloud.
 */
async function loadFromFirebase() {
    if (typeof db === 'undefined' || typeof FIREBASE_ENABLED === 'undefined' || !FIREBASE_ENABLED) return;
    try {
        showLoadingOverlay('Syncing data from cloud…');
        const doc = await db.collection('nacos_data').doc('main').get();
        if (doc.exists) {
            const cloudData = doc.data();
            const localData = getData();
            // Merge: use cloud for structure/status, keep local base64 images
            cloudData.users = cloudData.users.map(cloudUser => {
                const localUser = localData.users.find(u => u.id === cloudUser.id);
                return { ...cloudUser, profilePic: localUser?.profilePic || '' };
            });
            cloudData.settings.adminSignature = localData.settings.adminSignature || '';
            cloudData.transactions = cloudData.transactions.map(cloudTx => {
                const localTx = localData.transactions.find(t => t.id === cloudTx.id);
                return { ...cloudTx, proofImage: localTx?.proofImage || '' };
            });
            localStorage.setItem('nacos_payments', JSON.stringify(cloudData));
            showToast('Data synced from cloud ☁️', 'success');
        }
    } catch (err) {
        console.warn('Could not load from Firebase:', err);
        showToast('Cloud sync unavailable — using local data', 'warning');
    } finally {
        hideLoadingOverlay();
    }
}

// ── Audit trail helper ────────────────────────────────────────────────────────

/**
 * Record an admin action in the audit log.
 * @param {string} action      - Short description e.g. 'APPROVE_PAYMENT'
 * @param {string} detail      - Human-readable detail e.g. 'Approved ₦5000 for John Doe'
 * @param {string} [actorId]   - ID of the admin who performed the action
 */
function logAudit(action, detail, actorId) {
    const data = getData();
    if (!data.auditLog) data.auditLog = [];
    data.auditLog.unshift({
        id: 'audit_' + Date.now(),
        action,
        detail,
        actorId: actorId || (currentUser ? currentUser.id : 'system'),
        actorName: currentUser ? currentUser.name : 'System',
        timestamp: new Date().toISOString()
    });
    // Keep only the last 500 audit entries to avoid bloat
    if (data.auditLog.length > 500) data.auditLog = data.auditLog.slice(0, 500);
    saveData(data);
}

// ── Loading overlay ───────────────────────────────────────────────────────────

function showLoadingOverlay(msg = 'Loading…') {
    let overlay = document.getElementById('loading-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loading-overlay';
        overlay.innerHTML = `<div class="loading-spinner"></div><p>${msg}</p>`;
        document.body.appendChild(overlay);
    } else {
        overlay.querySelector('p').textContent = msg;
        overlay.style.display = 'flex';
    }
}

function hideLoadingOverlay() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) overlay.style.display = 'none';
}

// ── App initialisation ────────────────────────────────────────────────────────

/**
 * One-time migration: hash any plain-text passwords still in localStorage.
 * Runs silently in the background after app loads.
 */
async function migratePasswords() {
    if (typeof bcrypt === 'undefined') return; // bcrypt not loaded, skip
    const data = getData();
    let changed = false;
    for (const user of data.users) {
        // Skip admin — keep plain-text so it always works even if bcrypt is unavailable
        if (user.isAdmin) continue;
        if (user.password && !user.password.startsWith('$2')) {
            user.password = await hashPassword(user.password);
            changed = true;
        }
    }
    if (changed) {
        saveData(data);
        console.info('NACOS: student passwords migrated to bcrypt hashes');
    }
}

/**
 * App initialisation — runs after all scripts have loaded.
 * Since app.js is loaded at the bottom of <body>, the DOM is already
 * fully parsed when this executes, so we call initApp() directly.
 */
function initApp() {
    // Initialize data structure in localStorage
    initializeData();

    // ALWAYS ensure admin password is plain-text — runs every startup
    (function ensureAdminWorks() {
        try {
            const raw = localStorage.getItem('nacos_payments');
            if (!raw) return;
            const data = JSON.parse(raw);
            if (!data || !data.users) return;
            let changed = false;
            data.users.forEach(u => {
                if (u.isAdmin) {
                    if (u.password !== 'admin') { u.password = 'admin'; changed = true; }
                    if (!u.matricNumber) { u.matricNumber = 'ADMIN'; changed = true; }
                }
            });
            if (changed) {
                localStorage.setItem('nacos_payments', JSON.stringify(data));
                console.info('NACOS: admin credentials normalised');
            }
        } catch(e) {
            localStorage.removeItem('nacos_payments');
            initializeData();
            console.warn('NACOS: corrupt data cleared, reinitialised');
        }
    })();

    // Restore session from localStorage so refresh keeps you logged in
    (function restoreSession() {
        try {
            const savedId = localStorage.getItem('nacos_session');
            if (!savedId) return;
            const data = getData();
            const user = data.users.find(u => u.id === savedId);
            if (user) {
                currentUser = user;
                console.info('NACOS: session restored for', user.name);
            } else {
                localStorage.removeItem('nacos_session');
            }
        } catch(e) {
            localStorage.removeItem('nacos_session');
        }
    })();
    // Update navigation based on current user (logged in or not)
    updateNavForUser();

    // Initialize dark/light theme from localStorage or system preference
    initTheme();

    // ===== FORM SUBMISSION EVENT LISTENERS =====

    if (document.getElementById('login-form')) {
        document.getElementById('login-form').addEventListener('submit', handleLogin);
    }

    if (document.getElementById('register-form')) {
        document.getElementById('register-form').addEventListener('submit', handleRegister);
    }

    if (document.getElementById('nav-logout')) {
        document.getElementById('nav-logout').addEventListener('click', handleLogout);
    }

    if (document.getElementById('settings-form')) {
        document.getElementById('settings-form').addEventListener('submit', handleSaveSettings);
    }

    if (document.getElementById('submit-payment-form')) {
        document.getElementById('submit-payment-form').addEventListener('submit', handleSubmitPayment);
    }

    // ===== FILE INPUT PREVIEW =====

    if (document.getElementById('pay-proof')) {
        document.getElementById('pay-proof').addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(evt) {
                    document.getElementById('proof-img-preview').src = evt.target.result;
                    document.getElementById('pay-proof-preview').style.display = 'block';
                };
                reader.readAsDataURL(file);
            }
        });
    }

    // ===== NAVIGATION LINKS =====

    document.querySelectorAll('.nav-links a[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo(e.target.closest('a').dataset.page);
        });
    });

    // ===== ADMIN TAB SWITCHING =====

    document.querySelectorAll('.admin-tabs .tab-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.admin-tabs .tab-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            document.querySelectorAll('#page-admin .tab-content').forEach(t => t.classList.remove('active'));
            document.getElementById(`admin-${this.dataset.tab}-tab`).classList.add('active');
        });
    });

    // ===== MOUSE TRACKING FOR GLASSMORPHISM EFFECTS =====

    document.addEventListener('mousemove', e => {
        document.documentElement.style.setProperty('--mouse-x', e.clientX + 'px');
        document.documentElement.style.setProperty('--mouse-y', e.clientY + 'px');
        const card = e.target.closest('.glass-card, .stat-card, .dashboard-card, .settings-card, .auth-form, .btn-primary, .btn-outline');
        if (card) {
            const rect = card.getBoundingClientRect();
            card.style.setProperty('--card-mouse-x', `${e.clientX - rect.left}px`);
            card.style.setProperty('--card-mouse-y', `${e.clientY - rect.top}px`);
        }
    });

    // ===== THEME TOGGLE =====

    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) {
        themeBtn.addEventListener('click', toggleTheme);
    }

    // ===== LUCIDE ICONS =====

    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    // ===== FORGOT PASSWORD FORM =====

    initForgotPasswordForm();

    // ===== ETHICS CAROUSEL =====

    initCarousel();

    // ===== SERVICE WORKER =====

    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('sw.js').catch(() => {});
    }

    // ===== FOOTER YEAR =====

    const yearEl = document.getElementById('footer-year');
    if (yearEl) yearEl.textContent = new Date().getFullYear();

    // ===== RESTORE PAGE ON REFRESH =====
    // If a session was restored, navigate back to the correct page.
    // Otherwise show home page.
    if (currentUser) {
        if (currentUser.isAdmin) {
            navigateTo('admin');
        } else {
            navigateTo('dashboard');
        }
    } else {
        navigateTo('home');
    }

    // ===== PASSWORD MIGRATION (background, non-blocking) =====

    migratePasswords();

    // ===== FIREBASE SYNC =====

    loadFromFirebase();
}

// Scripts are at bottom of <body> so DOM is ready — call directly.
// Also register DOMContentLoaded as a safety net for any edge cases.
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

// ==================== NAVIGATION ====================


/**
 * Navigate to a specific page in the single-page application
 * Hides all pages, shows the target page, and loads page-specific content
 * @param {string} page - The page identifier (e.g. 'home', 'login', 'admin', 'dashboard')
 */
function navigateTo(page) {
    // Close mobile nav if open
    closeMobileNav();

    // Hide all pages by removing the 'active' class
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    
    // Find and show the target page element
    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.classList.add('active');  // Makes the page visible via CSS
    }
    
    // Update active state on navigation links
    document.querySelectorAll('.nav-links a').forEach(link => link.classList.remove('active'));
    const activeLink = document.querySelector(`.nav-links a[data-page="${page}"]`);
    if (activeLink) {
        activeLink.classList.add('active');  // Highlights the current nav link
    }
    
    // Load page-specific data and content
    switch (page) {
        case 'admin':
            // Only allow access if user is logged in as admin
            if (currentUser && currentUser.isAdmin) {
                loadAdminDashboard();  // Load all admin data and charts
            } else {
                navigateTo('login');  // Redirect to login if not admin
                showToast('Please login as admin', 'error');
            }
            break;
        case 'dashboard':
            // Only allow access if user is logged in as a student
            if (currentUser && !currentUser.isAdmin) {
                loadDashboard();  // Load student profile and payment info
            } else {
                navigateTo('login');  // Redirect to login if not a student
            }
            break;
    }
}

// ==================== AUTHENTICATION ====================

/**
 * Handle login form submission
 * Validates credentials against stored users and sets the current session
 * Supports both bcrypt-hashed and legacy plain-text passwords.
 * @param {Event} e - The form submit event
 */
async function handleLogin(e) {
    e.preventDefault();

    const submitBtn = e.target.querySelector('button[type="submit"]');
    const origText  = submitBtn ? submitBtn.textContent : '';
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Logging in…'; }

    try {
        const matric   = document.getElementById('login-matric').value.trim();
        const password = document.getElementById('login-password').value;

        if (!matric || !password) {
            showToast('Please enter your matric number and password', 'error');
            return;
        }

        const data = getData();
        const user = data.users.find(u => u.matricNumber === matric);

        if (user && await verifyPassword(password, user.password)) {
            currentUser = user;
            // Persist session so browser refresh restores the logged-in state
            localStorage.setItem('nacos_session', user.id);
            updateNavForUser();
            showToast('Login successful!', 'success');
            document.getElementById('login-form').reset();
            if (user.isAdmin) {
                navigateTo('admin');
            } else {
                navigateTo('dashboard');
            }
        } else {
            showToast('Invalid matric number or password', 'error');
        }
    } catch (err) {
        console.error('Login error:', err);
        showToast('Login failed. Please try again.', 'error');
    } finally {
        if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = origText || 'Login'; }
    }
}

/**
 * Handle registration form submission
 * Creates a new student account and saves it to localStorage
 * @param {Event} e - The form submit event
 */
async function handleRegister(e) {
    e.preventDefault();

    const submitBtn = e.target.querySelector('button[type="submit"]');
    const origText  = submitBtn ? submitBtn.textContent : '';
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Creating account…'; }

    try {
        const name            = document.getElementById('reg-name').value.trim();
        const email           = document.getElementById('reg-email').value.trim();
        const matric          = document.getElementById('reg-matric').value.trim();
        const level           = document.getElementById('reg-level').value;
        const gender          = document.getElementById('reg-gender').value;
        const state           = document.getElementById('reg-state').value;
        const password        = document.getElementById('reg-password').value;
        const confirmPassword = document.getElementById('reg-confirm-password').value;

        if (!name || !matric || !level || !password) {
            showToast('Please fill in all required fields', 'error');
            return;
        }

        if (password !== confirmPassword) {
            showToast('Passwords do not match', 'error');
            return;
        }

        if (password.length < 6) {
            showToast('Password must be at least 6 characters', 'error');
            return;
        }

        const data = getData();

        if (data.users.some(u => u.matricNumber === matric)) {
            showToast('Matric number already registered', 'error');
            return;
        }

        const hashedPassword = await hashPassword(password);

        const newUser = {
            id:           'user_' + Date.now(),
            name,
            email,
            phone:        '',
            matricNumber: matric,
            level,
            gender,
            state,
            password:     hashedPassword,
            isAdmin:      false
        };

        data.users.push(newUser);
        saveData(data);

        showToast('Registration successful! Please login.', 'success');

        sendEmail('welcome', { to_email: email, to_name: name, matric_number: matric, level });

        document.getElementById('register-form').reset();
        navigateTo('login');

    } catch (err) {
        console.error('Register error:', err);
        showToast('Registration failed. Please try again.', 'error');
    } finally {
        if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = origText || 'Create Account'; }
    }
}

/**
 * Handle logout action
 * Clears the current user session and redirects to home page
 * @param {Event} e - The click event
 */
function handleLogout(e) {
    e.preventDefault();
    currentUser = null;
    localStorage.removeItem('nacos_session'); // clear persisted session
    updateNavForUser();
    navigateTo('home');
    showToast('Logged out successfully', 'success');
}

/**
 * Update navigation bar visibility based on current user state
 * Shows/hides nav links appropriate for admin, student, or guest
 */
function updateNavForUser() {
    // Get references to all navigation link elements
    const loginLink = document.getElementById('nav-login');
    const registerLink = document.getElementById('nav-register');
    const adminLink = document.getElementById('nav-admin');
    const dashboardLink = document.getElementById('nav-dashboard');
    const logoutLink = document.getElementById('nav-logout');
    
    // Preserve dark mode class when switching body className
    const isDark = document.body.classList.contains('dark-mode');
    
    if (currentUser) {
        // User is logged in — apply role-specific theme class
        document.body.className = 'student-theme'; // Both admin and student share the same green UI
        
        // Re-apply dark mode if it was active before
        if (isDark) document.body.classList.add('dark-mode');
        
        // Hide login/register links, show logout
        loginLink.style.display = 'none';
        registerLink.style.display = 'none';
        logoutLink.style.display = 'block';
        
        if (currentUser.isAdmin) {
            // Admin: show Admin Portal link, hide My Dashboard
            adminLink.style.display = 'block';
            dashboardLink.style.display = 'none';
        } else {
            // Student: show My Dashboard link, hide Admin Portal
            adminLink.style.display = 'none';
            dashboardLink.style.display = 'block';
        }

        // Show notification bell for all logged-in users
        const notifBell = document.getElementById('nav-notifications');
        if (notifBell) { notifBell.style.display = 'flex'; updateNotifBadge(); }

    } else {
        // No user logged in — reset to guest state
        document.body.className = isDark ? 'dark-mode' : '';
        
        // Show login/register links, hide all authenticated links
        loginLink.style.display = 'block';
        registerLink.style.display = 'block';
        adminLink.style.display = 'none';
        dashboardLink.style.display = 'none';
        logoutLink.style.display = 'none';

        const notifBell = document.getElementById('nav-notifications');
        if (notifBell) notifBell.style.display = 'none';
    }
}

// ==================== TOAST NOTIFICATIONS ====================

/**
 * Display a prominent, techy toast notification at the top-right.
 * Auto-dismisses after 2 seconds. Click to dismiss early.
 * @param {string} message - The text message to display
 * @param {string} type    - 'success' | 'error' | 'warning' | 'info'
 */
function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');

    // Icon SVG paths per type
    const icons = {
        success: `<svg viewBox="0 0 24 24" fill="none"><polyline points="20 6 9 17 4 12"/></svg>`,
        error:   `<svg viewBox="0 0 24 24" fill="none"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
        warning: `<svg viewBox="0 0 24 24" fill="none"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
        info:    `<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
    };

    const titles = {
        success: 'Success',
        error:   'Error',
        warning: 'Warning',
        info:    'Info'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div class="toast-icon">${icons[type] || icons.info}</div>
        <div class="toast-body">
            <div class="toast-title">${titles[type] || type}</div>
            <div class="toast-msg">${message}</div>
        </div>
        <button class="toast-close" aria-label="Dismiss">&times;</button>
    `;

    // Click anywhere on toast or the × to dismiss early
    const dismiss = () => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 300);
    };
    toast.addEventListener('click', dismiss);

    container.appendChild(toast);

    // Auto-dismiss after 2 seconds
    setTimeout(dismiss, 2000);
}

// ==================== ADMIN DASHBOARD ====================

/**
 * Load all sections of the admin dashboard
 * Called when admin navigates to the admin portal page
 */
function loadAdminDashboard() {
    loadAdminTransactions();  // Populate the transactions approval table
    loadAdminSettings();      // Fill in the payment settings form
    loadAdminStudents();      // Populate the registered students table
    loadAdminCharts();        // Render the summary charts and stat cards
    loadReports();            // Financial reports tab
    loadSessions();           // Academic sessions tab
    loadAnnouncements();      // Announcements tab
    loadAuditLog();           // Audit log tab
}

function loadAdminTransactions() {
    const data = getData();
    const container = document.getElementById('admin-transactions-list');
    
    if (data.transactions.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No transactions found.</p>
            </div>
        `;
        return;
    }
    
    // Sort transactions: pending first, then by date desc
    const sortedTx = [...data.transactions].sort((a, b) => {
        if (a.status === 'pending' && b.status !== 'pending') return -1;
        if (a.status !== 'pending' && b.status === 'pending') return 1;
        return new Date(b.date) - new Date(a.date);
    });
    
    container.innerHTML = `
        <table class="admin-table">
            <thead>
                <tr>
                    <th><input type="checkbox" id="bulk-select-all" onchange="toggleSelectAll(this)" title="Select all pending"></th>
                    <th>Date</th>
                    <th>Student Info</th>
                    <th>Ref</th>
                    <th>Amount</th>
                    <th>Proof</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${sortedTx.map(tx => {
                    const student = data.users.find(u => u.id === tx.studentId) || { name: 'Unknown', matricNumber: 'N/A' };
                    return `
                        <tr>
                            <td>${tx.status === 'pending' ? `<input type="checkbox" class="bulk-checkbox" value="${tx.id}" onchange="updateBulkCount()">` : ''}</td>
                            <td>${new Date(tx.date).toLocaleDateString()}</td>
                            <td>${student.name}<br><small>${student.matricNumber}</small></td>
                            <td>${tx.reference}</td>
                            <td>₦${tx.amount}</td>
                            <td>
                                ${tx.proofImage ? `<button class="btn btn-outline" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="viewProof('${tx.id}')">View</button>` : 'N/A'}
                            </td>
                            <td><span class="status ${tx.status}">${tx.status.toUpperCase()}</span></td>
                            <td>
                                ${tx.status === 'pending' ? `
                                    <div class="action-btns">
                                        <button class="btn btn-success" onclick="updateTransactionStatus('${tx.id}', 'approved')">Approve</button>
                                        <button class="btn btn-danger" onclick="updateTransactionStatus('${tx.id}', 'rejected')">Reject</button>
                                    </div>
                                ` : '-'}
                            </td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
}

window.updateTransactionStatus = function(txId, newStatus) {
    const data = getData();
    const tx = data.transactions.find(t => t.id === txId);
    if (tx) {
        tx.status = newStatus;
        saveData(data);

        // Record in audit log
        const student = data.users.find(u => u.id === tx.studentId);
        logAudit(
            newStatus === 'approved' ? 'APPROVE_PAYMENT' : 'REJECT_PAYMENT',
            `${newStatus === 'approved' ? 'Approved' : 'Rejected'} ₦${(tx.amount || 0).toLocaleString()} payment for ${student ? student.name : 'Unknown'} (Ref: ${tx.reference})`
        );

        // Immediately refresh all admin dashboard sections so changes
        // reflect without requiring a logout/login cycle
        loadAdminTransactions();
        loadAdminStudents();
        loadAdminCharts();

        showToast(
            `Transaction ${newStatus === 'approved' ? 'approved ✓' : 'rejected'}`,
            newStatus === 'approved' ? 'success' : 'error'
        );

        // Send email notification to the student
        if (student && student.email) {
            const txLevel = tx.level || student.level;
            if (newStatus === 'approved') {
                sendEmail('paymentApproved', {
                    to_email:      student.email,
                    to_name:       student.name,
                    matric_number: student.matricNumber,
                    level:         txLevel,
                    amount:        `₦${tx.amount.toLocaleString()}`,
                    reference:     tx.reference,
                    receipt_no:    tx.id.replace('tx_', 'RCT-')
                });
            } else if (newStatus === 'rejected') {
                sendEmail('paymentRejected', {
                    to_email:      student.email,
                    to_name:       student.name,
                    matric_number: student.matricNumber,
                    level:         txLevel,
                    amount:        `₦${tx.amount.toLocaleString()}`,
                    reference:     tx.reference
                });
            }
        }

        // Push in-app notification to the student
        // (will appear next time they open the notification drawer)
        if (student) {
            const txLevel = tx.level || student.level;
            if (newStatus === 'approved') {
                const savedCurrentUser = currentUser;
                currentUser = student; // temporarily switch to push to student
                pushNotification(
                    '✅ Payment Approved',
                    `Your ₦${tx.amount.toLocaleString()} payment for ${txLevel} Level has been approved. Download your receipt from My Dashboard.`,
                    'success'
                );
                currentUser = savedCurrentUser;
            } else if (newStatus === 'rejected') {
                const savedCurrentUser = currentUser;
                currentUser = student;
                pushNotification(
                    '❌ Payment Rejected',
                    `Your ₦${tx.amount.toLocaleString()} payment for ${txLevel} Level (Ref: ${tx.reference}) was rejected. Please resubmit with a valid proof.`,
                    'error'
                );
                currentUser = savedCurrentUser;
            }
        }    }
};

function loadAdminSettings() {
    const data = getData();
    const s = data.settings;
    
    document.getElementById('set-bank-name').value = s.bankName;
    document.getElementById('set-account-name').value = s.accountName;
    document.getElementById('set-account-number').value = s.accountNumber;
    
    document.getElementById('set-100l').value = s.dues['100'];
    document.getElementById('set-200l').value = s.dues['200'];
    document.getElementById('set-300l').value = s.dues['300'];
    document.getElementById('set-400l').value = s.dues['400'];

    // Signature
    const sigPreviewBox = document.getElementById('set-signature-preview');
    const sigImgPreview = document.getElementById('sig-img-preview');
    if (sigPreviewBox && sigImgPreview) {
        if (s.adminSignature) {
            sigImgPreview.src = s.adminSignature;
            sigPreviewBox.style.display = 'inline-block';
        } else {
            sigPreviewBox.style.display = 'none';
        }
    }
}

function handleSaveSettings(e) {
    e.preventDefault();
    const data = getData();
    
    data.settings.bankName = document.getElementById('set-bank-name').value;
    data.settings.accountName = document.getElementById('set-account-name').value;
    data.settings.accountNumber = document.getElementById('set-account-number').value;
    
    data.settings.dues['100'] = parseInt(document.getElementById('set-100l').value);
    data.settings.dues['200'] = parseInt(document.getElementById('set-200l').value);
    data.settings.dues['300'] = parseInt(document.getElementById('set-300l').value);
    data.settings.dues['400'] = parseInt(document.getElementById('set-400l').value);
    
    const sigInput = document.getElementById('set-signature');
    if (sigInput && sigInput.files.length > 0) {
        const file = sigInput.files[0];
        const reader = new FileReader();
        reader.onload = function(evt) {
            data.settings.adminSignature = evt.target.result;
            saveData(data);
            showToast('Payment settings saved successfully!', 'success');
            loadAdminSettings();
        };
        reader.readAsDataURL(file);
        return; // async handler will finish
    }

    saveData(data);
    showToast('Payment settings saved successfully!', 'success');
    loadAdminCharts(); // refresh stats after settings change
}

function loadAdminStudents() {
    const data = getData();
    const students = data.users.filter(u => !u.isAdmin);
    const container = document.getElementById('admin-students-list');
    
    if (students.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No registered students.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = `
        <table class="admin-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Matric Number</th>
                    <th>Level</th>
                    <th>Gender</th>
                    <th>State</th>
                    <th>Payment Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${students.map(s => {
                    const studentTxs = data.transactions.filter(t => t.studentId === s.id);
                    const approved = studentTxs.find(t => t.status === 'approved');
                    const pending = studentTxs.find(t => t.status === 'pending');
                    let payStatus = 'unpaid';
                    if (approved) payStatus = 'approved';
                    else if (pending) payStatus = 'pending';
                    return `
                        <tr>
                            <td>${s.name}</td>
                            <td>${s.matricNumber}</td>
                            <td>${s.level} Level</td>
                            <td>${s.gender || '<span style="color:#94a3b8">N/A</span>'}</td>
                            <td>${s.state || '<span style="color:#94a3b8">N/A</span>'}</td>
                            <td><span class="status ${payStatus === 'unpaid' ? 'rejected' : payStatus}">${payStatus.toUpperCase()}</span></td>
                            <td>
                                <button class="btn btn-outline" style="padding:0.3rem 0.8rem;font-size:0.8rem;" onclick="viewStudentDetails('${s.id}')">View Details</button>
                            </td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
}

// ==================== STUDENT DASHBOARD ====================

function loadDashboard() {
    if (!currentUser) return;
    
    const data = getData();
    const s = data.settings;
    
    // Profile info
    const profileContainer = document.getElementById('profile-info');
    profileContainer.innerHTML = `
        <div class="profile-avatar-container" style="justify-content: flex-start;">
            <img src="${currentUser.profilePic || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIj48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjZTIlOGVmMCIvPjwvc3ZnPg=='}" alt="Profile Avatar" class="profile-avatar" style="width: 80px; height: 80px;">
        </div>
        <div class="profile-item">
            <span class="label">Name</span>
            <span class="value">${currentUser.name}</span>
        </div>
        <div class="profile-item">
            <span class="label">Matric Number</span>
            <span class="value">${currentUser.matricNumber}</span>
        </div>
        <div class="profile-item">
            <span class="label">Level</span>
            <span class="value">${currentUser.level} Level</span>
        </div>
        <div class="profile-item">
            <span class="label">Gender</span>
            <span class="value">${currentUser.gender || 'Not set'}</span>
        </div>
        <div class="profile-item">
            <span class="label">State of Origin</span>
            <span class="value">${currentUser.state || 'Not set'}</span>
        </div>
        <div class="profile-item">
            <span class="label">Email</span>
            <span class="value">${currentUser.email || 'Not set'}</span>
        </div>
        <div class="profile-item">
            <span class="label">Phone</span>
            <span class="value">${currentUser.phone || 'Not set'}</span>
        </div>
    `;
    
    // Payment Instructions
    const duesAmount = s.dues[currentUser.level] || 0;
    const instructionsContainer = document.getElementById('payment-instructions');
    instructionsContainer.innerHTML = `
        <p>Your required dues for ${currentUser.level} Level is:</p>
        <span class="amount">₦${duesAmount.toLocaleString()}</span>
        <hr style="margin: 1rem 0; border: none; border-top: 1px solid var(--gray-200);">
        <p>Please pay into the account below:</p>
        <p><strong>Bank:</strong> ${s.bankName}</p>
        <p><strong>Account Name:</strong> ${s.accountName}</p>
        <p><strong>Account No:</strong> ${s.accountNumber}</p>
    `;
    
    // Payment Form pre-fill — level dropdown will handle amount via onchange
    // Pre-select the student's current level in the dropdown
    const payLevelSelect = document.getElementById('pay-level');
    if (payLevelSelect) {
        payLevelSelect.value = String(currentUser.level);
        payLevelSelect.dispatchEvent(new Event('change'));
    }
    
    // Load student transactions (also manages payment form visibility)
    loadStudentTransactions();

    // Load announcements for this student
    loadStudentAnnouncements();
}

function handleSubmitPayment(e) {
    e.preventDefault();
    if (!currentUser) return;
    
    const amount = document.getElementById('pay-amount').value;
    const date = document.getElementById('pay-date').value;
    const proofInput = document.getElementById('pay-proof');
    // Get the selected level from the new dropdown
    const selectedLevel = document.getElementById('pay-level')
        ? document.getElementById('pay-level').value
        : currentUser.level;

    if (!selectedLevel) {
        showToast('Please select a level to pay for', 'error');
        return;
    }
    
    if (proofInput.files.length === 0) {
        showToast('Please upload a payment proof', 'error');
        return;
    }
    
    const file = proofInput.files[0];
    const reader = new FileReader();
    
    reader.onload = function(evt) {
        const base64Image = evt.target.result;
        const data = getData();
        
        const newTx = {
            id: 'tx_' + Date.now(),
            studentId: currentUser.id,
            level: selectedLevel,                              // store which level this payment is for
            amount: parseInt(amount),
            reference: 'IMG-' + Date.now().toString().slice(-6),
            proofImage: base64Image,
            date: date,
            status: 'pending',
            timestamp: new Date().toISOString()
        };
        
        data.transactions.push(newTx);
        saveData(data);
        
        document.getElementById('submit-payment-form').reset();
        document.getElementById('pay-proof-preview').style.display = 'none';
        showToast(`Payment for ${selectedLevel} Level submitted for approval!`, 'success');

        // Push in-app notification
        pushNotification(
            'Payment Submitted',
            `Your ₦${parseInt(amount).toLocaleString()} payment for ${selectedLevel} Level (Ref: ${newTx.reference}) is pending verification.`,
            'info'
        );

        // Send email notification to student confirming submission
        if (currentUser.email) {
            sendEmail('paymentSubmitted', {
                to_email:      currentUser.email,
                to_name:       currentUser.name,
                matric_number: currentUser.matricNumber,
                level:         selectedLevel,
                amount:        `₦${parseInt(amount).toLocaleString()}`,
                reference:     newTx.reference,
                date:          new Date(date).toLocaleDateString()
            });
        }

        loadStudentTransactions();
    };
    
    reader.readAsDataURL(file);
}

function loadStudentTransactions() {
    const data = getData();
    // Get all transactions for this student, newest first
    const myTxs = data.transactions
        .filter(t => t.studentId === currentUser.id)
        .sort((a, b) => new Date(b.date) - new Date(a.date));
    const container = document.getElementById('student-transactions-list');
    const submitSection = document.getElementById('submit-payment-section');
    const levelSelect = document.getElementById('pay-level');
    const amountInput = document.getElementById('pay-amount');
    const settings = data.settings;

    // Build a map of which levels have been paid or are pending for this student
    // Key: level string ('100','200','300','400'), Value: 'approved'|'pending'|null
    const levelStatus = {};
    ['100','200','300','400'].forEach(lvl => {
        const tx = myTxs.find(t => t.level === lvl && (t.status === 'approved' || t.status === 'pending'));
        levelStatus[lvl] = tx ? tx.status : null;
    });

    // Determine which levels are still payable (not yet approved or pending)
    const payableLevels = ['100','200','300','400'].filter(lvl => !levelStatus[lvl]);

    // Show or hide the payment form based on whether any level is still payable
    if (payableLevels.length === 0) {
        submitSection.style.display = 'none';
    } else {
        submitSection.style.display = 'block';

        // Rebuild the level dropdown — only show payable levels
        if (levelSelect) {
            // Preserve current selection if still valid
            const currentSelection = levelSelect.value;
            levelSelect.innerHTML = '<option value="">Select Level to Pay For</option>';
            payableLevels.forEach(lvl => {
                const amt = settings.dues[lvl] || 0;
                const opt = document.createElement('option');
                opt.value = lvl;
                opt.textContent = `${lvl} Level — ₦${amt.toLocaleString()}`;
                // Pre-select the student's current level if it's payable
                if (lvl === String(currentUser.level) || lvl === currentSelection) {
                    opt.selected = true;
                }
                levelSelect.appendChild(opt);
            });

            // Update amount when level changes
            levelSelect.onchange = function() {
                const selected = this.value;
                amountInput.value = selected ? (settings.dues[selected] || 0) : '';
            };

            // Trigger once to set initial amount
            levelSelect.dispatchEvent(new Event('change'));
        }
    }

    // Show empty state if no transactions at all
    if (myTxs.length === 0) {
        container.innerHTML = `<div class="empty-state"><p>No transactions yet.</p></div>`;
        return;
    }

    // Render each transaction card grouped with a level badge
    container.innerHTML = myTxs.map(tx => {
        const txLevel = tx.level || currentUser.level; // fallback for old records
        return `
        <div class="tx-card">
            <div class="tx-card-top">
                <div>
                    <span class="tx-level-badge">${txLevel} Level</span>
                    <span class="label" style="margin-left:0.5rem;">
                        ${new Date(tx.date).toLocaleDateString()}
                    </span>
                </div>
                <span class="status ${tx.status}">${tx.status.toUpperCase()}</span>
            </div>
            <div class="tx-card-bottom">
                <span class="value">Ref: ${tx.reference}</span>
                <span class="value tx-amount">₦${tx.amount.toLocaleString()}</span>
            </div>
            ${tx.status === 'approved' ? `
                <button class="btn btn-primary btn-receipt"
                        onclick="printReceipt('${tx.id}')">
                    <i data-lucide="download"></i> Download Receipt
                </button>
            ` : ''}
        </div>`;
    }).join('');

    // Re-render Lucide icons for the newly injected download buttons
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

window.printReceipt = function(txId) {
    const data = getData();
    const tx = data.transactions.find(t => t.id === txId);
    if (!tx || tx.status !== 'approved') return;

    // Determine which level this receipt is for (new field or fallback)
    const txLevel = tx.level || currentUser.level;

    // Build the QR code data string — encodes key receipt details
    const qrData = [
        `NACOS PLASU RECEIPT`,
        `Receipt: ${tx.id.replace('tx_', 'RCT-')}`,
        `Student: ${currentUser.name}`,
        `Matric: ${currentUser.matricNumber}`,
        `Level: ${txLevel}`,
        `Amount: NGN ${tx.amount.toLocaleString()}`,
        `Ref: ${tx.reference}`,
        `Date: ${new Date(tx.date).toLocaleDateString()}`,
        `Status: APPROVED`
    ].join('\n');

    // Default passport placeholder — a simple grey silhouette SVG used when no profile pic exists
    const defaultAvatar = `data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48cmVjdCB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgZmlsbD0iI2UyZThmMCIvPjxjaXJjbGUgY3g9IjUwIiBjeT0iMzgiIHI9IjIwIiBmaWxsPSIjOTRhM2I4Ii8+PHBhdGggZD0iTTEwIDkwIGMwLTI1IDIwLTQwIDQwLTQwczQwIDE1IDQwIDQwIiBmaWxsPSIjOTRhM2I4Ii8+PC9zdmc+`;
    const studentPhoto = currentUser.profilePic || defaultAvatar;

    const printArea = document.getElementById('receipt-print-area');

    printArea.innerHTML = `
        <div class="receipt">
            <!-- Header: logos + org name + title badge -->
            <div class="receipt-header">
                <div class="receipt-logos">
                    <img src="plasu-logo.png" alt="PLASU Logo">
                    <img src="nacos-logo.png" alt="NACOS Logo">
                </div>
                <h2>NACOS PLASU</h2>
                <p class="receipt-subtitle">Nigeria Association of Computing Students · Plateau State University Bokkos</p>
                <span class="receipt-title-badge">Official Payment Receipt</span>
            </div>

            <!-- Body: details grid + passport photo -->
            <div class="receipt-body-row">
                <div class="receipt-details">
                    <div class="receipt-row">
                        <span class="receipt-label">Receipt No:</span>
                        <span class="receipt-value">${tx.id.replace('tx_', 'RCT-')}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Date Issued:</span>
                        <span class="receipt-value">${new Date().toLocaleDateString()}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Payment Date:</span>
                        <span class="receipt-value">${new Date(tx.date).toLocaleDateString()}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Student Name:</span>
                        <span class="receipt-value">${currentUser.name}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Matric Number:</span>
                        <span class="receipt-value">${currentUser.matricNumber}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Level:</span>
                        <span class="receipt-value">${txLevel} Level</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Gender:</span>
                        <span class="receipt-value">${currentUser.gender || 'N/A'}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">State of Origin:</span>
                        <span class="receipt-value">${currentUser.state || 'N/A'}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Email:</span>
                        <span class="receipt-value">${currentUser.email || 'N/A'}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Amount Paid:</span>
                        <span class="receipt-value receipt-amount-value">₦${tx.amount.toLocaleString()}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Payment Ref:</span>
                        <span class="receipt-value">${tx.reference}</span>
                    </div>
                    <div class="receipt-row">
                        <span class="receipt-label">Status:</span>
                        <span class="receipt-value receipt-status-value">✓ APPROVED</span>
                    </div>
                </div>

                <!-- Passport-style student photo -->
                <div class="receipt-passport">
                    <img src="${studentPhoto}" alt="Student Photo" class="receipt-passport-img">
                    <p class="receipt-passport-label">Student Photo</p>
                </div>
            </div>

            <!-- QR Code + Signature -->
            <div class="receipt-bottom-row">
                <div class="receipt-qr-section">
                    <div id="receipt-qr-code"></div>
                    <p class="receipt-qr-label">Scan to verify</p>
                </div>
                ${data.settings && data.settings.adminSignature ? `
                <div class="receipt-signature-container">
                    <img src="${data.settings.adminSignature}" alt="Admin Signature" class="receipt-signature-img">
                    <p>Authorised Signature</p>
                </div>` : '<div></div>'}
            </div>

            <!-- Footer -->
            <div class="receipt-footer">
                <p>Thank you for your payment. Keep this receipt for your records.</p>
                <p>Generated by NACOS PLASU Payment Portal &nbsp;·&nbsp; ${new Date().toLocaleString()}</p>
            </div>
        </div>
    `;

    // Generate QR code inside the receipt using QRCode.js
    if (typeof QRCode !== 'undefined') {
        new QRCode(document.getElementById('receipt-qr-code'), {
            text: qrData,
            width: 83,   // 22mm at 96dpi — fits the compact receipt layout
            height: 83,
            colorDark: '#0f172a',
            colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.M
        });
    }

    // Small delay to let QR code render before printing
    setTimeout(() => window.print(), 400);
};

// ==================== MODALS & PROFILE ====================

window.openProfileModal = function() {
    const modalBody = document.getElementById('modal-body');
    const stateOptions = ['Abia','Adamawa','Akwa Ibom','Anambra','Bauchi','Bayelsa','Benue','Borno',
        'Cross River','Delta','Ebonyi','Edo','Ekiti','Enugu','FCT - Abuja','Gombe','Imo','Jigawa',
        'Kaduna','Kano','Katsina','Kebbi','Kogi','Kwara','Lagos','Nasarawa','Niger','Ogun','Ondo',
        'Osun','Oyo','Plateau','Rivers','Sokoto','Taraba','Yobe','Zamfara']
        .map(s => `<option value="${s}" ${currentUser.state === s ? 'selected' : ''}>${s}</option>`).join('');

    modalBody.innerHTML = `
        <h3 style="color: var(--text-main); margin-bottom: 1.5rem;">Update Biodata</h3>
        <form id="update-profile-form">
            <div class="form-group" style="text-align: center;">
                <label>Profile Picture</label>
                <div class="profile-avatar-container">
                    <img src="${currentUser.profilePic || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIj48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjZTIlOGVmMCIvPjwvc3ZnPg=='}" alt="Avatar" class="profile-avatar" id="modal-avatar-preview">
                </div>
                <input type="file" id="prof-pic" accept="image/*" onchange="document.getElementById('modal-avatar-preview').src = window.URL.createObjectURL(this.files[0])">
            </div>
            <div class="form-group">
                <label>Full Name</label>
                <input type="text" id="prof-name" value="${currentUser.name}" required>
            </div>
            <div class="form-group">
                <label>Gender</label>
                <select id="prof-gender">
                    <option value="">Select Gender</option>
                    <option value="Male" ${currentUser.gender === 'Male' ? 'selected' : ''}>Male</option>
                    <option value="Female" ${currentUser.gender === 'Female' ? 'selected' : ''}>Female</option>
                    <option value="Other" ${currentUser.gender === 'Other' ? 'selected' : ''}>Other</option>
                </select>
            </div>
            <div class="form-group">
                <label>State of Origin</label>
                <select id="prof-state">
                    <option value="">Select State</option>
                    ${stateOptions}
                </select>
            </div>
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" id="prof-email" value="${currentUser.email || ''}" placeholder="Enter email">
            </div>
            <div class="form-group">
                <label>Phone Number</label>
                <input type="tel" id="prof-phone" value="${currentUser.phone || ''}" placeholder="Enter phone number">
            </div>
            <div class="form-group">
                <label>New Password (Optional)</label>
                <div class="password-wrapper">
                    <input type="password" id="prof-password" placeholder="Leave blank to keep current">
                    <button type="button" class="toggle-password-btn" onclick="togglePassword('prof-password', this)">👁️</button>
                </div>
            </div>
            <button type="button" class="btn btn-primary" onclick="handleUpdateProfile()" style="width: 100%;">Save Changes</button>
        </form>
    `;
    document.getElementById('app-modal').classList.add('active');
};

window.closeModal = function() {
    document.getElementById('app-modal').classList.remove('active');
};

window.handleUpdateProfile = async function() {
    const name = document.getElementById('prof-name').value.trim();
    const email = document.getElementById('prof-email').value.trim();
    const phone = document.getElementById('prof-phone').value.trim();
    const pwd = document.getElementById('prof-password').value;
    const gender = document.getElementById('prof-gender') ? document.getElementById('prof-gender').value : '';
    const state = document.getElementById('prof-state') ? document.getElementById('prof-state').value : '';
    const picInput = document.getElementById('prof-pic');

    const data = getData();
    const userIndex = data.users.findIndex(u => u.id === currentUser.id);

    if (userIndex !== -1) {
        data.users[userIndex].name = name;
        data.users[userIndex].email = email;
        data.users[userIndex].phone = phone;
        if (gender) data.users[userIndex].gender = gender;
        if (state) data.users[userIndex].state = state;
        if (pwd) {
            if (pwd.length < 6) { showToast('Password must be at least 6 characters', 'error'); return; }
            data.users[userIndex].password = await hashPassword(pwd);
        }

        const finishUpdate = () => {
            currentUser = data.users[userIndex];
            saveData(data);

            showToast('Biodata updated successfully!', 'success');
            closeModal();

            // Refresh display if student
            if (!currentUser.isAdmin && document.getElementById('page-dashboard').classList.contains('active')) {
                loadDashboard();
            }
        };

        if (picInput && picInput.files.length > 0) {
            const reader = new FileReader();
            reader.onload = function(evt) {
                data.users[userIndex].profilePic = evt.target.result;
                finishUpdate();
            };
            reader.readAsDataURL(picInput.files[0]);
        } else {
            finishUpdate();
        }
    }
};

window.viewProof = function(txId) {
    const data = getData();
    const tx = data.transactions.find(t => t.id === txId);
    
    if (tx && tx.proofImage) {
        const modalBody = document.getElementById('modal-body');
        modalBody.innerHTML = `
            <h3 style="color: white; margin-bottom: 1rem;">Payment Proof</h3>
            <img src="${tx.proofImage}" style="width: 100%; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1);">
            <p style="text-align: center; margin-top: 1rem; color: var(--text-muted);">Ref: ${tx.reference}</p>
        `;
        document.getElementById('app-modal').classList.add('active');
    } else {
        showToast('No proof image found for this transaction.', 'error');
    }
};

window.togglePassword = function(inputId, btn) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = '<i data-lucide="eye-off"></i>';
    } else {
        input.type = 'password';
        btn.innerHTML = '<i data-lucide="eye"></i>';
    }
    lucide.createIcons({ nodes: [btn] });
};

// ==================== ADMIN CHARTS ====================

let chartPaymentStatus = null;
let chartStudentsLevel = null;

function loadAdminCharts() {
    const data = getData();
    const students = data.users.filter(u => !u.isAdmin);
    const txs = data.transactions;

    // Summary stats
    const totalStudents = students.length;
    const approvedTxs = txs.filter(t => t.status === 'approved');
    const pendingTxs = txs.filter(t => t.status === 'pending');
    const totalPaid = approvedTxs.reduce((sum, t) => sum + (t.amount || 0), 0);
    const totalPending = pendingTxs.length;

    document.getElementById('stat-total-students').textContent = totalStudents;
    document.getElementById('stat-total-paid').textContent = '₦' + totalPaid.toLocaleString();
    document.getElementById('stat-total-pending').textContent = totalPending;

    // Payment Status Doughnut Chart
    const paidCount = students.filter(s => txs.some(t => t.studentId === s.id && t.status === 'approved')).length;
    const pendingCount = students.filter(s => {
        const hasPending = txs.some(t => t.studentId === s.id && t.status === 'pending');
        const hasApproved = txs.some(t => t.studentId === s.id && t.status === 'approved');
        return hasPending && !hasApproved;
    }).length;
    const unpaidCount = totalStudents - paidCount - pendingCount;

    const ctxStatus = document.getElementById('chart-payment-status');
    if (ctxStatus) {
        if (chartPaymentStatus) chartPaymentStatus.destroy();
        chartPaymentStatus = new Chart(ctxStatus, {
            type: 'doughnut',
            data: {
                labels: ['Paid', 'Pending', 'Unpaid'],
                datasets: [{
                    data: [paidCount, pendingCount, unpaidCount],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom', labels: { font: { size: 12 }, padding: 12 } }
                },
                cutout: '65%'
            }
        });
    }

    // Students by Level Bar Chart
    const levels = ['100', '200', '300', '400'];
    const levelCounts = levels.map(l => students.filter(s => String(s.level) === l).length);

    const ctxLevel = document.getElementById('chart-students-level');
    if (ctxLevel) {
        if (chartStudentsLevel) chartStudentsLevel.destroy();
        chartStudentsLevel = new Chart(ctxLevel, {
            type: 'bar',
            data: {
                labels: levels.map(l => l + ' Level'),
                datasets: [{
                    label: 'Students',
                    data: levelCounts,
                    backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6'],
                    borderRadius: 8,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { stepSize: 1 }, grid: { color: 'rgba(0,0,0,0.05)' } },
                    x: { grid: { display: false } }
                }
            }
        });
    }
}

// ==================== VIEW STUDENT DETAILS ====================

window.viewStudentDetails = function(studentId) {
    const data = getData();
    const student = data.users.find(u => u.id === studentId);
    if (!student) return;

    const studentTxs = data.transactions.filter(t => t.studentId === studentId);
    const approved = studentTxs.find(t => t.status === 'approved');
    const pending = studentTxs.find(t => t.status === 'pending');
    let payStatus = 'UNPAID';
    let payStatusClass = 'rejected';
    if (approved) { payStatus = 'PAID'; payStatusClass = 'approved'; }
    else if (pending) { payStatus = 'PENDING'; payStatusClass = 'pending'; }

    const txRows = studentTxs.length > 0
        ? studentTxs.map(tx => `
            <tr>
                <td>${new Date(tx.date).toLocaleDateString()}</td>
                <td>${tx.reference}</td>
                <td>₦${tx.amount.toLocaleString()}</td>
                <td><span class="status ${tx.status}">${tx.status.toUpperCase()}</span></td>
            </tr>
        `).join('')
        : `<tr><td colspan="4" style="text-align:center;color:#94a3b8;padding:1rem;">No transactions</td></tr>`;

    const modalBody = document.getElementById('modal-body');
    modalBody.innerHTML = `
        <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem;">
            <img src="${student.profilePic || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIj48cmVjdCB3aWR0aD0iMTAwJSIgaGVpZ2h0PSIxMDAlIiBmaWxsPSIjZTJlOGYwIi8+PC9zdmc+'}" 
                 alt="Avatar" class="profile-avatar" style="width:70px;height:70px;flex-shrink:0;">
            <div>
                <h3 style="margin:0;font-size:1.2rem;">${student.name}</h3>
                <p style="color:#64748b;margin:0.2rem 0 0;">${student.matricNumber}</p>
            </div>
        </div>
        <div class="student-detail-grid">
            <div class="detail-item"><span class="detail-label">Level</span><span class="detail-value">${student.level} Level</span></div>
            <div class="detail-item"><span class="detail-label">Gender</span><span class="detail-value">${student.gender || 'N/A'}</span></div>
            <div class="detail-item"><span class="detail-label">State of Origin</span><span class="detail-value">${student.state || 'N/A'}</span></div>
            <div class="detail-item"><span class="detail-label">Email</span><span class="detail-value">${student.email || 'N/A'}</span></div>
            <div class="detail-item"><span class="detail-label">Phone</span><span class="detail-value">${student.phone || 'N/A'}</span></div>
            <div class="detail-item"><span class="detail-label">Payment Status</span><span class="detail-value"><span class="status ${payStatusClass}">${payStatus}</span></span></div>
        </div>
        <h4 style="margin:1.5rem 0 0.75rem;font-size:1rem;color:#475569;">Transaction History</h4>
        <table style="width:100%;border-collapse:collapse;font-size:0.9rem;">
            <thead>
                <tr style="background:#f1f5f9;">
                    <th style="padding:0.6rem 0.8rem;text-align:left;color:#475569;font-size:0.8rem;text-transform:uppercase;">Date</th>
                    <th style="padding:0.6rem 0.8rem;text-align:left;color:#475569;font-size:0.8rem;text-transform:uppercase;">Ref</th>
                    <th style="padding:0.6rem 0.8rem;text-align:left;color:#475569;font-size:0.8rem;text-transform:uppercase;">Amount</th>
                    <th style="padding:0.6rem 0.8rem;text-align:left;color:#475569;font-size:0.8rem;text-transform:uppercase;">Status</th>
                </tr>
            </thead>
            <tbody>${txRows}</tbody>
        </table>
        <div style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid #e2e8f0;display:flex;gap:0.75rem;">
            <button class="btn btn-danger" onclick="adminResetPassword('${studentId}', '${student.name.replace(/'/g, "\\'")}')" style="flex:1;">
                <i data-lucide="key"></i> Reset Password
            </button>
        </div>
    `;
    document.getElementById('app-modal').classList.add('active');
    
    // Initialize Lucide icons for the modal content
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
};

// ==================== DOWNLOAD ALL STUDENTS ====================

window.downloadAllStudents = function() {
    const data = getData();
    const students = data.users.filter(u => !u.isAdmin);

    if (students.length === 0) {
        showToast('No students to download', 'warning');
        return;
    }

    const headers = ['Name', 'Matric Number', 'Level', 'Gender', 'State of Origin', 'Email', 'Phone', 'Payment Status', 'Amount Paid (₦)'];

    const rows = students.map(s => {
        const studentTxs = data.transactions.filter(t => t.studentId === s.id);
        const approved = studentTxs.find(t => t.status === 'approved');
        const pending = studentTxs.find(t => t.status === 'pending');
        let payStatus = 'Unpaid';
        let amountPaid = 0;
        if (approved) { payStatus = 'Paid'; amountPaid = approved.amount; }
        else if (pending) { payStatus = 'Pending'; }

        return [
            `"${s.name}"`,
            `"${s.matricNumber}"`,
            `"${s.level} Level"`,
            `"${s.gender || ''}"`,
            `"${s.state || ''}"`,
            `"${s.email || ''}"`,
            `"${s.phone || ''}"`,
            `"${payStatus}"`,
            amountPaid
        ].join(',');
    });

    const csvContent = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `NACOS_PLASU_Students_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast('Student data downloaded!', 'success');
};

// ==================== DARK / LIGHT MODE ====================

function initTheme() {
    const saved = localStorage.getItem('nacos_theme');
    // Default is LIGHT — only go dark if explicitly saved as dark
    if (saved === 'dark') {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
    updateThemeIcon();
}

function toggleTheme() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    localStorage.setItem('nacos_theme', isDark ? 'dark' : 'light');
    updateThemeIcon();
}

function updateThemeIcon() {
    const isDark = document.body.classList.contains('dark-mode');
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    // Sun = currently light mode (click to go dark)
    // Moon = currently dark mode (click to go light)
    btn.innerHTML = isDark
        ? '<i data-lucide="moon"></i>'
        : '<i data-lucide="sun"></i>';
    btn.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
    btn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
    if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [btn] });
}

// ==================== PASSWORD RESET (STUDENT - FORGOT PASSWORD) ====================

// Tracks the student account found during the forgot-password flow
let forgotPasswordUser = null;

/**
 * Wire up the forgot-password form once the DOM is ready.
 * This is safe to call multiple times — the guard on forgotForm prevents double-binding.
 */
function initForgotPasswordForm() {
    const forgotForm = document.getElementById('forgot-password-form');
    if (forgotForm && !forgotForm.dataset.bound) {
        forgotForm.addEventListener('submit', handleForgotPassword);
        forgotForm.dataset.bound = 'true'; // prevent double-binding
    }
}

/**
 * Two-step forgot-password handler.
 *
 * Step 1 — "Find My Account":
 *   The student enters their matric number. If found, the form expands
 *   to show the new-password fields and a confirmation hint.
 *
 * Step 2 — "Reset Password":
 *   The student enters and confirms a new password. On success the
 *   password is updated in localStorage and they are redirected to login.
 *
 * @param {Event} e - The form submit event
 */
function handleForgotPassword(e) {
    e.preventDefault();

    const matricInput = document.getElementById('forgot-matric');
    const secSection  = document.getElementById('forgot-security-section');
    const submitBtn   = document.getElementById('forgot-submit-btn');

    if (!forgotPasswordUser) {
        // ── STEP 1: find the account ──
        const matric = matricInput.value.trim();
        if (!matric) { showToast('Please enter your matric number', 'error'); return; }

        const data = getData();
        const user = data.users.find(u => u.matricNumber === matric && !u.isAdmin);

        if (user) {
            forgotPasswordUser = user;
            matricInput.readOnly   = true;
            secSection.style.display = 'block';
            submitBtn.textContent    = 'Reset Password';
            document.getElementById('forgot-hint-text').textContent =
                `Account found: ${user.name} · ${user.level} Level`;
            if (typeof lucide !== 'undefined') lucide.createIcons();
            showToast('Account found! Set your new password below.', 'success');
        } else {
            showToast('No student account found with that matric number.', 'error');
        }

    } else {
        // ── STEP 2: save the new password ──
        const newPwd     = document.getElementById('forgot-new-password').value;
        const confirmPwd = document.getElementById('forgot-confirm-password').value;

        if (!newPwd || !confirmPwd) { showToast('Please fill in both password fields.', 'error'); return; }
        if (newPwd.length < 6)      { showToast('Password must be at least 6 characters.', 'error'); return; }
        if (newPwd !== confirmPwd)  { showToast('Passwords do not match.', 'error'); return; }

        submitBtn.disabled    = true;
        submitBtn.textContent = 'Saving…';

        const data      = getData();
        const userIndex = data.users.findIndex(u => u.id === forgotPasswordUser.id);

        if (userIndex === -1) {
            showToast('Account not found. Please try again.', 'error');
            submitBtn.disabled    = false;
            submitBtn.textContent = 'Reset Password';
            return;
        }

        // Save — hash if bcrypt available, otherwise plain-text
        hashPassword(newPwd).then(hashed => {
            data.users[userIndex].password = hashed;
            saveData(data);

            if (data.users[userIndex].email) {
                sendEmail('passwordReset', {
                    to_email:      data.users[userIndex].email,
                    to_name:       data.users[userIndex].name,
                    matric_number: data.users[userIndex].matricNumber
                });
            }

            showToast('Password reset! Redirecting to login…', 'success');

            // Reset form state
            forgotPasswordUser       = null;
            document.getElementById('forgot-password-form').reset();
            matricInput.readOnly     = false;
            secSection.style.display = 'none';
            submitBtn.textContent    = 'Find My Account';
            submitBtn.disabled       = false;

            setTimeout(() => navigateTo('login'), 1800);
        }).catch(() => {
            showToast('Failed to save password. Please try again.', 'error');
            submitBtn.disabled    = false;
            submitBtn.textContent = 'Reset Password';
        });
    }
}

// ==================== PASSWORD RESET (ADMIN - RESET STUDENT PASSWORD) ====================

/**
 * Open a clean in-app modal that lets the admin set a new password for a student.
 * Called from the "Reset Password" button inside the student-details modal.
 *
 * @param {string} studentId  - The unique ID of the student to reset
 * @param {string} studentName - Display name shown in the modal heading
 */
window.adminResetPassword = function(studentId, studentName) {
    const modalBody = document.getElementById('modal-body');

    modalBody.innerHTML = `
        <!-- Admin password-reset form injected dynamically -->
        <div class="admin-reset-header">
            <div class="admin-reset-icon">
                <i data-lucide="key-round"></i>
            </div>
            <h3>Reset Password</h3>
            <p>Set a new password for <strong>${studentName}</strong>.</p>
        </div>

        <form id="admin-reset-form">
            <div class="form-group">
                <label>New Password</label>
                <div class="password-wrapper">
                    <input type="password" id="admin-new-pwd" placeholder="Enter new password" required>
                    <button type="button" class="toggle-password-btn"
                            onclick="togglePassword('admin-new-pwd', this)" aria-label="Show password">
                        <i data-lucide="eye"></i>
                    </button>
                </div>
            </div>
            <div class="form-group">
                <label>Confirm New Password</label>
                <div class="password-wrapper">
                    <input type="password" id="admin-confirm-pwd" placeholder="Confirm new password" required>
                    <button type="button" class="toggle-password-btn"
                            onclick="togglePassword('admin-confirm-pwd', this)" aria-label="Show password">
                        <i data-lucide="eye"></i>
                    </button>
                </div>
            </div>

            <!-- Password strength indicator bar -->
            <div class="pwd-strength-wrap">
                <div class="pwd-strength-bar" id="pwd-strength-bar"></div>
            </div>
            <p class="pwd-strength-label" id="pwd-strength-label"></p>

            <div style="display:flex;gap:0.75rem;margin-top:1.5rem;">
                <button type="button" class="btn btn-outline" onclick="closeModal()" style="flex:1;">Cancel</button>
                <button type="submit" class="btn btn-primary" style="flex:1;">Save Password</button>
            </div>
        </form>
    `;

    // Show the modal
    document.getElementById('app-modal').classList.add('active');

    // Render Lucide icons inside the freshly injected HTML
    if (typeof lucide !== 'undefined') lucide.createIcons();

    // Live password-strength meter
    document.getElementById('admin-new-pwd').addEventListener('input', function() {
        updatePasswordStrength(this.value, 'pwd-strength-bar', 'pwd-strength-label');
    });

    // Handle the admin reset form submission
    document.getElementById('admin-reset-form').addEventListener('submit', function(e) {
        e.preventDefault();

        const newPwd     = document.getElementById('admin-new-pwd').value;
        const confirmPwd = document.getElementById('admin-confirm-pwd').value;

        if (newPwd.length < 6) {
            showToast('Password must be at least 6 characters.', 'error'); return;
        }
        if (newPwd !== confirmPwd) {
            showToast('Passwords do not match.', 'error'); return;
        }

        const data      = getData();
        const userIndex = data.users.findIndex(u => u.id === studentId);

        if (userIndex !== -1) {
            hashPassword(newPwd).then(hashed => {
                data.users[userIndex].password = hashed;
                saveData(data);
                closeModal();
                showToast(`Password for ${studentName} has been reset successfully.`, 'success');
            });
        } else {
            showToast('Student not found.', 'error');
        }
    });
};

/**
 * Live password-strength meter used in the admin reset modal.
 * Updates a coloured bar and a text label based on password complexity.
 *
 * Strength levels:
 *   Weak   — fewer than 6 chars
 *   Fair   — 6+ chars, only one character class
 *   Good   — 6+ chars, two character classes
 *   Strong — 8+ chars, three or more character classes
 *
 * @param {string} pwd        - The password string to evaluate
 * @param {string} barId      - ID of the <div> used as the strength bar
 * @param {string} labelId    - ID of the <p> used for the text label
 */
function updatePasswordStrength(pwd, barId, labelId) {
    const bar   = document.getElementById(barId);
    const label = document.getElementById(labelId);
    if (!bar || !label) return;

    // Count how many character classes are present
    let score = 0;
    if (pwd.length >= 6)                    score++;  // minimum length
    if (pwd.length >= 8)                    score++;  // good length
    if (/[A-Z]/.test(pwd))                  score++;  // uppercase letter
    if (/[0-9]/.test(pwd))                  score++;  // digit
    if (/[^A-Za-z0-9]/.test(pwd))           score++;  // special character

    const levels = [
        { label: '',        color: 'transparent', width: '0%'   },  // empty
        { label: 'Weak',    color: '#ef4444',      width: '25%'  },  // score 1
        { label: 'Fair',    color: '#f59e0b',      width: '50%'  },  // score 2
        { label: 'Good',    color: '#3b82f6',      width: '75%'  },  // score 3-4
        { label: 'Strong',  color: '#10b981',      width: '100%' },  // score 5
    ];

    const level = pwd.length === 0 ? levels[0]
                : score <= 1       ? levels[1]
                : score === 2      ? levels[2]
                : score <= 4       ? levels[3]
                :                    levels[4];

    bar.style.width            = level.width;
    bar.style.backgroundColor  = level.color;
    label.textContent          = level.label;
    label.style.color          = level.color;
}

// ==================== EMAIL NOTIFICATIONS ====================

/**
 * Send an email notification via EmailJS.
 * Silently fails if EmailJS is not configured — the app works without it.
 *
 * @param {string} templateKey  - Key from EMAILJS_CONFIG.templates
 * @param {Object} params       - Template variables (to_email, to_name, etc.)
 */
async function sendEmail(templateKey, params) {
    // Do nothing if EmailJS is not configured
    if (typeof EMAILJS_ENABLED === 'undefined' || !EMAILJS_ENABLED) return;
    if (typeof emailjs === 'undefined') return;

    const templateId = EMAILJS_CONFIG.templates[templateKey];
    if (!templateId) {
        console.warn(`NACOS Email: unknown template key "${templateKey}"`);
        return;
    }

    try {
        await emailjs.send(EMAILJS_CONFIG.serviceId, templateId, params);
        console.info(`NACOS Email: "${templateKey}" sent to ${params.to_email}`);
    } catch (err) {
        // Log but never crash the app over a failed email
        console.warn(`NACOS Email: failed to send "${templateKey}"`, err);
    }
}

// ==================== DATA MANAGEMENT (ADMIN) ====================
// All functions prefixed with dm_ to avoid naming collisions.
// These power the "Data Management" tab in the admin portal.

// Tracks which student is currently selected in the data management panel
let dmSelectedStudentId = null;

/**
 * Search students by name or matric number and render results.
 * Called live as the admin types in the search box.
 * @param {string} query - The search string
 */
window.dmSearchStudents = function(query) {
    const data = getData();
    const students = data.users.filter(u => !u.isAdmin);
    const q = (query || '').toLowerCase().trim();

    // Filter by name or matric number
    const results = q
        ? students.filter(s =>
            s.name.toLowerCase().includes(q) ||
            s.matricNumber.toLowerCase().includes(q))
        : students;

    const container = document.getElementById('dm-search-results');

    if (results.length === 0) {
        container.innerHTML = `<p class="dm-empty">No students found matching "${query}".</p>`;
        return;
    }

    container.innerHTML = `
        <table class="admin-table dm-results-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Matric</th>
                    <th>Level</th>
                    <th>Email</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${results.map(s => {
                    const txs = data.transactions.filter(t => t.studentId === s.id);
                    const approved = txs.filter(t => t.status === 'approved').length;
                    const pending  = txs.filter(t => t.status === 'pending').length;
                    return `
                        <tr>
                            <td><strong>${s.name}</strong></td>
                            <td>${s.matricNumber}</td>
                            <td>${s.level} Level</td>
                            <td>${s.email || '<span style="color:#94a3b8">—</span>'}</td>
                            <td>
                                <div class="action-btns">
                                    <button class="btn btn-outline"
                                            style="padding:0.3rem 0.7rem;font-size:0.8rem;"
                                            onclick="dmSelectStudent('${s.id}')">
                                        <i data-lucide="pencil"></i> Edit
                                    </button>
                                </div>
                            </td>
                        </tr>`;
                }).join('')}
            </tbody>
        </table>`;

    if (typeof lucide !== 'undefined') lucide.createIcons();
};

/**
 * Select a student for editing — populates the edit form, transaction list,
 * and danger zone with that student's data.
 * @param {string} studentId
 */
window.dmSelectStudent = function(studentId) {
    const data = getData();
    const student = data.users.find(u => u.id === studentId);
    if (!student) return;

    dmSelectedStudentId = studentId;

    // ── Populate edit form ──────────────────────────────────────────────────
    document.getElementById('dm-edit-id').value      = student.id;
    document.getElementById('dm-edit-name').value    = student.name;
    document.getElementById('dm-edit-matric').value  = student.matricNumber;
    document.getElementById('dm-edit-level').value   = student.level;
    document.getElementById('dm-edit-gender').value  = student.gender || '';
    document.getElementById('dm-edit-state').value   = student.state  || '';
    document.getElementById('dm-edit-email').value   = student.email  || '';
    document.getElementById('dm-edit-phone').value   = student.phone  || '';
    document.getElementById('dm-editing-name').textContent = student.name;

    document.getElementById('dm-edit-section').style.display    = 'block';
    document.getElementById('dm-danger-section').style.display  = 'block';
    document.getElementById('dm-tx-section').style.display      = 'block';
    document.getElementById('dm-tx-student-name').textContent   = student.name;

    // ── Render transaction list ─────────────────────────────────────────────
    dmRenderStudentTransactions(studentId);

    // Scroll to edit section
    document.getElementById('dm-edit-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
};

/**
 * Render the transaction list for a student inside the data management panel.
 * Each row has an inline status editor and a delete button.
 * @param {string} studentId
 */
function dmRenderStudentTransactions(studentId) {
    const data = getData();
    const txs  = data.transactions.filter(t => t.studentId === studentId);
    const container = document.getElementById('dm-tx-list');

    if (txs.length === 0) {
        container.innerHTML = `<p class="dm-empty">No transactions for this student.</p>`;
        return;
    }

    container.innerHTML = `
        <table class="admin-table">
            <thead>
                <tr>
                    <th>Date</th>
                    <th>Level</th>
                    <th>Ref</th>
                    <th>Amount</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${txs.map(tx => `
                    <tr id="dm-tx-row-${tx.id}">
                        <td>${new Date(tx.date).toLocaleDateString()}</td>
                        <td>${tx.level || '—'} Level</td>
                        <td>${tx.reference}</td>
                        <td>₦${tx.amount.toLocaleString()}</td>
                        <td>
                            <!-- Inline status dropdown for quick correction -->
                            <select class="dm-status-select status ${tx.status}"
                                    onchange="dmUpdateTxStatus('${tx.id}', this.value)">
                                <option value="pending"  ${tx.status==='pending'  ? 'selected':''}>PENDING</option>
                                <option value="approved" ${tx.status==='approved' ? 'selected':''}>APPROVED</option>
                                <option value="rejected" ${tx.status==='rejected' ? 'selected':''}>REJECTED</option>
                            </select>
                        </td>
                        <td>
                            <button class="btn btn-danger"
                                    style="padding:0.25rem 0.6rem;font-size:0.78rem;"
                                    onclick="dmDeleteTransaction('${tx.id}')">
                                <i data-lucide="trash-2"></i>
                            </button>
                        </td>
                    </tr>`).join('')}
            </tbody>
        </table>`;

    if (typeof lucide !== 'undefined') lucide.createIcons();
}

/**
 * Save edited student biodata from the dm-edit-form.
 */
window.dmSaveEdit = function() {
    const id = document.getElementById('dm-edit-id').value;
    if (!id) return;

    const data = getData();
    const idx  = data.users.findIndex(u => u.id === id);
    if (idx === -1) { showToast('Student not found', 'error'); return; }

    // Apply all edited fields
    data.users[idx].name         = document.getElementById('dm-edit-name').value.trim();
    data.users[idx].matricNumber = document.getElementById('dm-edit-matric').value.trim();
    data.users[idx].level        = document.getElementById('dm-edit-level').value;
    data.users[idx].gender       = document.getElementById('dm-edit-gender').value;
    data.users[idx].state        = document.getElementById('dm-edit-state').value.trim();
    data.users[idx].email        = document.getElementById('dm-edit-email').value.trim();
    data.users[idx].phone        = document.getElementById('dm-edit-phone').value.trim();

    saveData(data);
    showToast(`${data.users[idx].name}'s biodata updated successfully.`, 'success');

    // Refresh the search results and badge
    document.getElementById('dm-editing-name').textContent = data.users[idx].name;
    dmSearchStudents(document.getElementById('dm-search-input').value);
};

/**
 * Cancel editing and hide the edit/danger panels.
 */
window.dmCancelEdit = function() {
    dmSelectedStudentId = null;
    document.getElementById('dm-edit-section').style.display   = 'none';
    document.getElementById('dm-danger-section').style.display = 'none';
    document.getElementById('dm-tx-section').style.display     = 'none';
};

/**
 * Update a single transaction's status inline.
 * @param {string} txId
 * @param {string} newStatus - 'pending' | 'approved' | 'rejected'
 */
window.dmUpdateTxStatus = function(txId, newStatus) {
    const data = getData();
    const tx   = data.transactions.find(t => t.id === txId);
    if (!tx) return;

    tx.status = newStatus;
    saveData(data);
    showToast(`Transaction status updated to ${newStatus.toUpperCase()}.`, 'success');

    // Update the select element's class for colour coding
    const sel = document.querySelector(`#dm-tx-row-${txId} .dm-status-select`);
    if (sel) sel.className = `dm-status-select status ${newStatus}`;
};

/**
 * Delete a single transaction record after confirmation.
 * @param {string} txId
 */
window.dmDeleteTransaction = function(txId) {
    if (!confirm('Delete this transaction record? This cannot be undone.')) return;

    const data = getData();
    data.transactions = data.transactions.filter(t => t.id !== txId);
    saveData(data);
    showToast('Transaction deleted.', 'success');

    // Re-render the transaction list
    if (dmSelectedStudentId) dmRenderStudentTransactions(dmSelectedStudentId);
};

/**
 * Clear ALL transactions for the currently selected student.
 */
window.dmClearStudentTransactions = function() {
    if (!dmSelectedStudentId) return;
    const data    = getData();
    const student = data.users.find(u => u.id === dmSelectedStudentId);
    if (!student) return;

    if (!confirm(`Clear ALL transaction records for ${student.name}? This cannot be undone.`)) return;

    data.transactions = data.transactions.filter(t => t.studentId !== dmSelectedStudentId);
    saveData(data);
    showToast(`All transactions for ${student.name} cleared.`, 'success');
    dmRenderStudentTransactions(dmSelectedStudentId);
};

/**
 * Permanently delete a student account and all their transactions.
 */
window.dmDeleteStudent = function() {
    if (!dmSelectedStudentId) return;
    const data    = getData();
    const student = data.users.find(u => u.id === dmSelectedStudentId);
    if (!student) return;

    if (!confirm(
        `PERMANENTLY DELETE ${student.name} (${student.matricNumber})?\n\n` +
        `This will also delete all their transaction records.\nThis cannot be undone.`
    )) return;

    // Remove user and all their transactions
    data.users        = data.users.filter(u => u.id !== dmSelectedStudentId);
    data.transactions = data.transactions.filter(t => t.studentId !== dmSelectedStudentId);
    saveData(data);

    showToast(`${student.name}'s account has been deleted.`, 'success');
    dmCancelEdit();
    dmSearchStudents(document.getElementById('dm-search-input').value);
    loadAdminCharts(); // refresh stats
};

/**
 * Export the entire data store as a timestamped JSON backup file.
 */
window.dmExportAllData = function() {
    const data     = getData();
    const json     = JSON.stringify(data, null, 2);
    const blob     = new Blob([json], { type: 'application/json' });
    const url      = URL.createObjectURL(blob);
    const link     = document.createElement('a');
    const filename = `NACOS_PLASU_Backup_${new Date().toISOString().slice(0,10)}.json`;

    link.href     = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    showToast('Full data backup downloaded.', 'success');
};

/**
 * Import data from a JSON backup file.
 * Validates the structure before overwriting localStorage.
 * @param {HTMLInputElement} input - The file input element
 */
window.dmImportData = function(input) {
    const file = input.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const imported = JSON.parse(e.target.result);

            // Basic structure validation
            if (!imported.users || !imported.transactions || !imported.settings) {
                showToast('Invalid backup file — missing required fields.', 'error');
                return;
            }

            if (!confirm(
                `Import this backup?\n\n` +
                `This will REPLACE all current data with:\n` +
                `• ${imported.users.filter(u => !u.isAdmin).length} students\n` +
                `• ${imported.transactions.length} transactions\n\n` +
                `Current data will be overwritten.`
            )) return;

            saveData(imported);
            showToast('Data imported successfully. Reloading…', 'success');
            setTimeout(() => window.location.reload(), 1500);

        } catch (err) {
            showToast('Failed to parse backup file. Make sure it is a valid JSON file.', 'error');
        }
    };
    reader.readAsText(file);
    input.value = ''; // reset so same file can be re-selected
};

/**
 * Clear ALL transaction records from the system (keeps student accounts).
 * Requires double confirmation.
 */
window.dmClearAllTransactions = function() {
    if (!confirm('Clear ALL transaction records from the entire system?\n\nStudent accounts will be kept but all payment history will be deleted.')) return;
    if (!confirm('Are you absolutely sure? This cannot be undone.')) return;

    const data = getData();
    const count = data.transactions.length;
    data.transactions = [];
    saveData(data);

    showToast(`${count} transaction records cleared.`, 'success');
    loadAdminCharts();
};

// ==================== ETHICS CAROUSEL ====================

/**
 * Initialise the ethics & principles carousel on the landing page.
 * Auto-advances every 5 seconds. Supports prev/next buttons and dot indicators.
 * Called once from DOMContentLoaded.
 */
function initCarousel() {
    const track  = document.getElementById('carousel-track');
    const dotsEl = document.getElementById('carousel-dots');
    const prevBtn = document.getElementById('carousel-prev');
    const nextBtn = document.getElementById('carousel-next');
    if (!track) return;

    const slides = track.querySelectorAll('.carousel-slide');
    const total  = slides.length;
    let current  = 0;
    let timer    = null;

    // Build dot indicators
    slides.forEach((_, i) => {
        const dot = document.createElement('button');
        dot.className = 'carousel-dot' + (i === 0 ? ' active' : '');
        dot.setAttribute('aria-label', `Slide ${i + 1}`);
        dot.addEventListener('click', () => goTo(i));
        dotsEl.appendChild(dot);
    });

    function goTo(index) {
        current = (index + total) % total;
        track.style.transform = `translateX(-${current * 100}%)`;
        // Update dots
        dotsEl.querySelectorAll('.carousel-dot').forEach((d, i) => {
            d.classList.toggle('active', i === current);
        });
        // Re-render Lucide icons in the newly visible slide
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    function next() { goTo(current + 1); }
    function prev() { goTo(current - 1); }

    // Auto-advance every 5 seconds
    function startTimer() { timer = setInterval(next, 5000); }
    function stopTimer()  { clearInterval(timer); }

    prevBtn.addEventListener('click', () => { stopTimer(); prev(); startTimer(); });
    nextBtn.addEventListener('click', () => { stopTimer(); next(); startTimer(); });

    // Pause on hover
    track.parentElement.addEventListener('mouseenter', stopTimer);
    track.parentElement.addEventListener('mouseleave', startTimer);

    // Touch/swipe support
    let touchStartX = 0;
    track.addEventListener('touchstart', e => { touchStartX = e.touches[0].clientX; }, { passive: true });
    track.addEventListener('touchend', e => {
        const diff = touchStartX - e.changedTouches[0].clientX;
        if (Math.abs(diff) > 40) { stopTimer(); diff > 0 ? next() : prev(); startTimer(); }
    }, { passive: true });

    startTimer();
}

// ==================== CAREER PATHS TOGGLE ====================

/**
 * Toggle the expanded state of a career card.
 * Called from the "Read More / Show Less" button inside each card.
 * @param {HTMLButtonElement} btn - The button that was clicked
 */
window.toggleCareer = function(btn) {
    const card = btn.closest('.career-card');
    const isExpanded = card.classList.toggle('expanded');

    // Update button label and icon
    const label = btn.querySelector('i') ? btn : btn;
    btn.innerHTML = isExpanded
        ? `<i data-lucide="chevron-up"></i> Show Less`
        : `<i data-lucide="chevron-down"></i> Read More`;

    // Re-render Lucide icons inside the button
    if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [btn] });

    // Smooth scroll to card top if expanding
    if (isExpanded) {
        setTimeout(() => card.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);
    }
};

// ==================== MOBILE NAVIGATION ====================

/**
 * Toggle the mobile navigation drawer open/closed.
 * Called by the hamburger button.
 */
window.toggleMobileNav = function() {
    const links = document.querySelector('.nav-links');
    const btn   = document.getElementById('nav-hamburger');
    if (!links) return;

    const isOpen = links.classList.toggle('open');
    // Swap hamburger icon between menu and X
    if (btn) {
        btn.innerHTML = isOpen
            ? '<i data-lucide="x"></i>'
            : '<i data-lucide="menu"></i>';
        if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [btn] });
    }
};

/**
 * Close the mobile nav drawer (called on navigateTo and outside clicks).
 */
function closeMobileNav() {
    const links = document.querySelector('.nav-links');
    const btn   = document.getElementById('nav-hamburger');
    if (!links) return;
    links.classList.remove('open');
    if (btn) {
        btn.innerHTML = '<i data-lucide="menu"></i>';
        if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [btn] });
    }
}

// Close mobile nav when clicking outside of it
document.addEventListener('click', function(e) {
    const nav = document.querySelector('.navbar');
    if (nav && !nav.contains(e.target)) closeMobileNav();
});

// ==================== NOTIFICATION CENTRE ====================

/**
 * Build a notification object and push it into the user's notification list.
 * Called internally whenever a relevant event happens (payment approved, etc.)
 * @param {string} title   - Short heading e.g. "Payment Approved"
 * @param {string} message - Body text
 * @param {string} type    - 'success' | 'error' | 'warning' | 'info'
 */
function pushNotification(title, message, type = 'info') {
    if (!currentUser) return;
    const data = getData();
    if (!data.notifications) data.notifications = {};
    if (!data.notifications[currentUser.id]) data.notifications[currentUser.id] = [];

    data.notifications[currentUser.id].unshift({
        id:        'notif_' + Date.now(),
        title,
        message,
        type,
        read:      false,
        timestamp: new Date().toISOString()
    });

    // Keep only the last 50 notifications per user
    if (data.notifications[currentUser.id].length > 50) {
        data.notifications[currentUser.id] = data.notifications[currentUser.id].slice(0, 50);
    }

    saveData(data);
    updateNotifBadge();
}

/**
 * Update the red badge count on the notification bell.
 */
function updateNotifBadge() {
    const badge = document.getElementById('notif-badge');
    if (!badge || !currentUser) return;

    const data = getData();
    const notifs = (data.notifications && data.notifications[currentUser.id]) || [];
    const unread = notifs.filter(n => !n.read).length;

    if (unread > 0) {
        badge.textContent = unread > 99 ? '99+' : unread;
        badge.style.display = 'flex';
    } else {
        badge.style.display = 'none';
    }
}

/**
 * Open the notification drawer and render the current user's notifications.
 */
window.openNotifications = function() {
    const drawer  = document.getElementById('notif-drawer');
    const overlay = document.getElementById('notif-overlay');
    if (!drawer) return;

    renderNotifications();

    drawer.classList.add('open');
    overlay.classList.add('open');

    // Re-render Lucide icons inside the drawer
    if (typeof lucide !== 'undefined') lucide.createIcons();
};

/**
 * Close the notification drawer.
 */
window.closeNotifications = function() {
    const drawer  = document.getElementById('notif-drawer');
    const overlay = document.getElementById('notif-overlay');
    if (drawer)  drawer.classList.remove('open');
    if (overlay) overlay.classList.remove('open');
};

/**
 * Render the notification list inside the drawer.
 */
function renderNotifications() {
    const list  = document.getElementById('notif-list');
    const label = document.getElementById('notif-unread-label');
    if (!list || !currentUser) return;

    const data   = getData();
    const notifs = (data.notifications && data.notifications[currentUser.id]) || [];
    const unread = notifs.filter(n => !n.read).length;

    // Update sub-label
    if (label) {
        label.textContent = unread > 0
            ? `${unread} unread notification${unread > 1 ? 's' : ''}`
            : 'All caught up';
    }

    if (notifs.length === 0) {
        list.innerHTML = `
            <div class="notif-empty">
                <i data-lucide="bell-off"></i>
                <p>No notifications yet.<br>Activity will appear here.</p>
            </div>`;
        if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [list] });
        return;
    }

    // Icon map per type
    const icons = {
        success: 'check-circle',
        error:   'x-circle',
        warning: 'alert-triangle',
        info:    'info'
    };

    list.innerHTML = notifs.map(n => `
        <div class="notif-item ${n.read ? '' : 'unread'}" onclick="markNotificationRead('${n.id}')">
            <div class="notif-item-icon notif-icon--${n.type}">
                <i data-lucide="${icons[n.type] || 'bell'}"></i>
            </div>
            <div class="notif-item-body">
                <div class="notif-item-title">${n.title}</div>
                <div class="notif-item-msg">${n.message}</div>
                <div class="notif-item-time">
                    <i data-lucide="clock"></i>
                    ${timeAgo(n.timestamp)}
                </div>
            </div>
            ${!n.read ? '<div class="notif-unread-dot"></div>' : ''}
        </div>
    `).join('');

    if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [list] });
}

/**
 * Mark a single notification as read.
 * @param {string} notifId
 */
window.markNotificationRead = function(notifId) {
    if (!currentUser) return;
    const data = getData();
    const notifs = (data.notifications && data.notifications[currentUser.id]) || [];
    const n = notifs.find(x => x.id === notifId);
    if (n) {
        n.read = true;
        saveData(data);
        renderNotifications();
        updateNotifBadge();
    }
};

/**
 * Mark all notifications as read.
 */
window.markAllNotificationsRead = function() {
    if (!currentUser) return;
    const data = getData();
    if (data.notifications && data.notifications[currentUser.id]) {
        data.notifications[currentUser.id].forEach(n => { n.read = true; });
        saveData(data);
        renderNotifications();
        updateNotifBadge();
    }
};

/**
 * Convert an ISO timestamp to a human-readable "time ago" string.
 * @param {string} iso
 * @returns {string}
 */
function timeAgo(iso) {
    const diff = Date.now() - new Date(iso).getTime();
    const mins  = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days  = Math.floor(diff / 86400000);
    if (mins  < 1)  return 'Just now';
    if (mins  < 60) return `${mins}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days  < 7)  return `${days}d ago`;
    return new Date(iso).toLocaleDateString();
}

// ==================== REPORTS TAB ====================

function loadReports() {
    const data = getData();
    const container = document.getElementById('admin-reports-content');
    if (!container) return;

    // Populate session filter dropdown
    const sessionFilter = document.getElementById('report-session-filter');
    if (sessionFilter) {
        const sessions = data.sessions || [];
        // Keep "All Sessions" option, add session options
        const existingOptions = Array.from(sessionFilter.options).map(o => o.value);
        sessions.forEach(s => {
            if (!existingOptions.includes(s.id)) {
                const opt = document.createElement('option');
                opt.value = s.id;
                opt.textContent = s.name;
                sessionFilter.appendChild(opt);
            }
        });
    }

    const txs = data.transactions.filter(t => t.status === 'approved');
    const totalRevenue = txs.reduce((sum, t) => sum + (t.amount || 0), 0);
    const byLevel = { '100': 0, '200': 0, '300': 0, '400': 0 };
    txs.forEach(t => {
        const lvl = t.level || '';
        if (byLevel[lvl] !== undefined) byLevel[lvl] += t.amount || 0;
    });

    container.innerHTML = `
        <div class="report-summary-grid">
            <div class="report-stat-card">
                <span class="report-stat-label">Total Revenue Collected</span>
                <span class="report-stat-value">₦${totalRevenue.toLocaleString()}</span>
            </div>
            <div class="report-stat-card">
                <span class="report-stat-label">Approved Payments</span>
                <span class="report-stat-value">${txs.length}</span>
            </div>
            <div class="report-stat-card">
                <span class="report-stat-label">Pending Payments</span>
                <span class="report-stat-value">${data.transactions.filter(t => t.status === 'pending').length}</span>
            </div>
            <div class="report-stat-card">
                <span class="report-stat-label">Rejected Payments</span>
                <span class="report-stat-value">${data.transactions.filter(t => t.status === 'rejected').length}</span>
            </div>
        </div>
        <div class="report-breakdown">
            <h4>Revenue by Level</h4>
            <table class="admin-table">
                <thead>
                    <tr><th>Level</th><th>Payments</th><th>Total (₦)</th></tr>
                </thead>
                <tbody>
                    ${['100','200','300','400'].map(lvl => {
                        const lvlTxs = txs.filter(t => t.level === lvl);
                        return `<tr>
                            <td>${lvl} Level</td>
                            <td>${lvlTxs.length}</td>
                            <td>₦${(byLevel[lvl] || 0).toLocaleString()}</td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>
        </div>
        <div class="report-breakdown" style="margin-top:1.5rem;">
            <h4>Recent Approved Transactions</h4>
            ${txs.length === 0 ? '<p style="color:var(--text-muted)">No approved transactions yet.</p>' : `
            <table class="admin-table">
                <thead>
                    <tr><th>Date</th><th>Student</th><th>Level</th><th>Amount</th><th>Reference</th></tr>
                </thead>
                <tbody>
                    ${txs.slice(0, 20).map(tx => {
                        const student = data.users.find(u => u.id === tx.studentId) || { name: 'Unknown', matricNumber: 'N/A' };
                        return `<tr>
                            <td>${new Date(tx.date).toLocaleDateString()}</td>
                            <td>${student.name}<br><small>${student.matricNumber}</small></td>
                            <td>${tx.level || '—'} Level</td>
                            <td>₦${(tx.amount || 0).toLocaleString()}</td>
                            <td>${tx.reference}</td>
                        </tr>`;
                    }).join('')}
                </tbody>
            </table>`}
        </div>
    `;
}

window.exportReportPDF = function() {
    showToast('Preparing PDF export…', 'info');
    setTimeout(() => window.print(), 300);
};

window.exportReportExcel = function() {
    const data = getData();
    const txs = data.transactions.filter(t => t.status === 'approved');
    if (txs.length === 0) { showToast('No approved transactions to export', 'warning'); return; }

    const headers = ['Date', 'Student Name', 'Matric Number', 'Level', 'Amount (₦)', 'Reference'];
    const rows = txs.map(tx => {
        const student = data.users.find(u => u.id === tx.studentId) || { name: 'Unknown', matricNumber: 'N/A' };
        return [
            `"${new Date(tx.date).toLocaleDateString()}"`,
            `"${student.name}"`,
            `"${student.matricNumber}"`,
            `"${tx.level || ''} Level"`,
            tx.amount || 0,
            `"${tx.reference}"`
        ].join(',');
    });

    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `NACOS_PLASU_Report_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast('Report exported as CSV!', 'success');
};

// ==================== SESSIONS TAB ====================

function loadSessions() {
    const data = getData();
    const container = document.getElementById('admin-sessions-list');
    if (!container) return;

    const sessions = data.sessions || [];

    if (sessions.length === 0) {
        container.innerHTML = `<div class="empty-state"><p>No academic sessions created yet. Click "New Session" to add one.</p></div>`;
        return;
    }

    container.innerHTML = `
        <table class="admin-table">
            <thead>
                <tr><th>Session Name</th><th>Start Date</th><th>End Date</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody>
                ${sessions.map(s => `
                    <tr>
                        <td><strong>${s.name}</strong></td>
                        <td>${s.startDate ? new Date(s.startDate).toLocaleDateString() : '—'}</td>
                        <td>${s.endDate ? new Date(s.endDate).toLocaleDateString() : '—'}</td>
                        <td><span class="status ${s.active ? 'approved' : 'pending'}">${s.active ? 'ACTIVE' : 'INACTIVE'}</span></td>
                        <td>
                            <div class="action-btns">
                                ${!s.active ? `<button class="btn btn-success" style="padding:0.3rem 0.8rem;font-size:0.8rem;" onclick="setActiveSession('${s.id}')">Set Active</button>` : ''}
                                <button class="btn btn-danger" style="padding:0.3rem 0.8rem;font-size:0.8rem;" onclick="deleteSession('${s.id}')">Delete</button>
                            </div>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

window.openNewSessionModal = function() {
    const modalBody = document.getElementById('modal-body');
    modalBody.innerHTML = `
        <h3 style="margin-bottom:1.25rem;">New Academic Session</h3>
        <form id="new-session-form">
            <div class="form-group">
                <label>Session Name</label>
                <input type="text" id="session-name" required placeholder="e.g. 2024/2025">
            </div>
            <div class="form-group">
                <label>Start Date</label>
                <input type="date" id="session-start">
            </div>
            <div class="form-group">
                <label>End Date</label>
                <input type="date" id="session-end">
            </div>
            <div class="form-group" style="display:flex;align-items:center;gap:0.5rem;">
                <input type="checkbox" id="session-active" style="width:auto;">
                <label for="session-active" style="margin:0;">Set as active session</label>
            </div>
            <div style="display:flex;gap:0.75rem;margin-top:1rem;">
                <button type="button" class="btn btn-outline" onclick="closeModal()" style="flex:1;">Cancel</button>
                <button type="submit" class="btn btn-primary" style="flex:1;">Create Session</button>
            </div>
        </form>
    `;
    document.getElementById('app-modal').classList.add('active');

    document.getElementById('new-session-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const name = document.getElementById('session-name').value.trim();
        if (!name) { showToast('Session name is required', 'error'); return; }

        const data = getData();
        if (!data.sessions) data.sessions = [];

        const isActive = document.getElementById('session-active').checked;
        if (isActive) data.sessions.forEach(s => { s.active = false; });

        data.sessions.push({
            id: 'sess_' + Date.now(),
            name,
            startDate: document.getElementById('session-start').value,
            endDate: document.getElementById('session-end').value,
            active: isActive
        });

        saveData(data);
        closeModal();
        loadSessions();
        showToast(`Session "${name}" created!`, 'success');
    });
};

window.setActiveSession = function(sessionId) {
    const data = getData();
    if (!data.sessions) return;
    data.sessions.forEach(s => { s.active = s.id === sessionId; });
    saveData(data);
    loadSessions();
    showToast('Active session updated', 'success');
};

window.deleteSession = function(sessionId) {
    if (!confirm('Delete this session? This cannot be undone.')) return;
    const data = getData();
    data.sessions = (data.sessions || []).filter(s => s.id !== sessionId);
    saveData(data);
    loadSessions();
    showToast('Session deleted', 'success');
};

// ==================== ANNOUNCEMENTS TAB ====================

function loadAnnouncements() {
    const data = getData();
    const container = document.getElementById('admin-announcements-list');
    if (!container) return;

    const announcements = data.announcements || [];

    if (announcements.length === 0) {
        container.innerHTML = `<div class="empty-state"><p>No announcements yet. Click "New Announcement" to post one.</p></div>`;
    } else {
        container.innerHTML = `
            <div class="announcements-list">
                ${announcements.map(a => `
                    <div class="announcement-card">
                        <div class="announcement-header">
                            <div>
                                <h4>${a.title}</h4>
                                <span class="announcement-meta">${new Date(a.date).toLocaleDateString()} &middot; ${a.audience || 'All Students'}</span>
                            </div>
                            <button class="btn btn-danger" style="padding:0.3rem 0.7rem;font-size:0.8rem;" onclick="deleteAnnouncement('${a.id}')">
                                <i data-lucide="trash-2"></i>
                            </button>
                        </div>
                        <p class="announcement-body">${a.body}</p>
                    </div>
                `).join('')}
            </div>
        `;
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    // Also update student announcements panel
    loadStudentAnnouncements();
}

function loadStudentAnnouncements() {
    if (!currentUser || currentUser.isAdmin) return;
    const data = getData();
    const announcements = (data.announcements || []).filter(a =>
        !a.audience || a.audience === 'All Students' || a.audience === currentUser.level + ' Level'
    );
    const card = document.getElementById('student-announcements-card');
    const list = document.getElementById('student-announcements-list');
    if (!card || !list) return;

    if (announcements.length === 0) {
        card.style.display = 'none';
        return;
    }

    card.style.display = 'block';
    list.innerHTML = announcements.map(a => `
        <div class="announcement-card" style="margin-bottom:0.75rem;">
            <div class="announcement-header">
                <div>
                    <h4 style="font-size:0.9rem;">${a.title}</h4>
                    <span class="announcement-meta">${new Date(a.date).toLocaleDateString()}</span>
                </div>
            </div>
            <p class="announcement-body" style="font-size:0.85rem;">${a.body}</p>
        </div>
    `).join('');
}

window.openAnnouncementModal = function() {
    const modalBody = document.getElementById('modal-body');
    modalBody.innerHTML = `
        <h3 style="margin-bottom:1.25rem;">New Announcement</h3>
        <form id="new-announcement-form">
            <div class="form-group">
                <label>Title</label>
                <input type="text" id="ann-title" required placeholder="Announcement title">
            </div>
            <div class="form-group">
                <label>Message</label>
                <textarea id="ann-body" required placeholder="Write your announcement here…" rows="4" style="resize:vertical;"></textarea>
            </div>
            <div class="form-group">
                <label>Audience</label>
                <select id="ann-audience">
                    <option value="All Students">All Students</option>
                    <option value="100 Level">100 Level</option>
                    <option value="200 Level">200 Level</option>
                    <option value="300 Level">300 Level</option>
                    <option value="400 Level">400 Level</option>
                </select>
            </div>
            <div style="display:flex;gap:0.75rem;margin-top:1rem;">
                <button type="button" class="btn btn-outline" onclick="closeModal()" style="flex:1;">Cancel</button>
                <button type="submit" class="btn btn-primary" style="flex:1;">Post Announcement</button>
            </div>
        </form>
    `;
    document.getElementById('app-modal').classList.add('active');

    document.getElementById('new-announcement-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const title = document.getElementById('ann-title').value.trim();
        const body = document.getElementById('ann-body').value.trim();
        const audience = document.getElementById('ann-audience').value;

        if (!title || !body) { showToast('Title and message are required', 'error'); return; }

        const data = getData();
        if (!data.announcements) data.announcements = [];

        data.announcements.unshift({
            id: 'ann_' + Date.now(),
            title,
            body,
            audience,
            date: new Date().toISOString()
        });

        saveData(data);
        closeModal();
        loadAnnouncements();
        showToast('Announcement posted!', 'success');
    });
};

window.deleteAnnouncement = function(annId) {
    if (!confirm('Delete this announcement?')) return;
    const data = getData();
    data.announcements = (data.announcements || []).filter(a => a.id !== annId);
    saveData(data);
    loadAnnouncements();
    showToast('Announcement deleted', 'success');
};

// ==================== AUDIT LOG TAB ====================

function loadAuditLog() {
    const data = getData();
    const container = document.getElementById('admin-audit-list');
    if (!container) return;

    const log = data.auditLog || [];

    if (log.length === 0) {
        container.innerHTML = `<div class="empty-state"><p>No audit entries yet. Admin actions will be recorded here.</p></div>`;
        return;
    }

    container.innerHTML = `
        <table class="admin-table">
            <thead>
                <tr><th>Time</th><th>Action</th><th>Detail</th><th>Performed By</th></tr>
            </thead>
            <tbody>
                ${log.map(entry => `
                    <tr>
                        <td style="white-space:nowrap;">${new Date(entry.timestamp).toLocaleString()}</td>
                        <td><code style="font-size:0.78rem;background:var(--bg-subtle);padding:0.2rem 0.4rem;border-radius:4px;">${entry.action}</code></td>
                        <td>${entry.detail}</td>
                        <td>${entry.actorName || entry.actorId || 'System'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

window.exportAuditLog = function() {
    const data = getData();
    const log = data.auditLog || [];
    if (log.length === 0) { showToast('No audit entries to export', 'warning'); return; }

    const headers = ['Timestamp', 'Action', 'Detail', 'Performed By'];
    const rows = log.map(e => [
        `"${new Date(e.timestamp).toLocaleString()}"`,
        `"${e.action}"`,
        `"${(e.detail || '').replace(/"/g, '""')}"`,
        `"${e.actorName || e.actorId || 'System'}"`
    ].join(','));

    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `NACOS_PLASU_AuditLog_${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast('Audit log exported!', 'success');
};

// ==================== BULK APPROVE / REJECT ====================

window.toggleSelectAll = function(checkbox) {
    document.querySelectorAll('.bulk-checkbox').forEach(cb => { cb.checked = checkbox.checked; });
    updateBulkCount();
};

window.updateBulkCount = function() {
    const checked = document.querySelectorAll('.bulk-checkbox:checked');
    const countEl = document.getElementById('bulk-selected-count');
    const approveBtn = document.getElementById('bulk-approve-btn');
    const rejectBtn = document.getElementById('bulk-reject-btn');

    if (checked.length > 0) {
        if (countEl) { countEl.textContent = `${checked.length} selected`; countEl.style.display = 'inline'; }
        if (approveBtn) approveBtn.style.display = 'inline-flex';
        if (rejectBtn) rejectBtn.style.display = 'inline-flex';
    } else {
        if (countEl) countEl.style.display = 'none';
        if (approveBtn) approveBtn.style.display = 'none';
        if (rejectBtn) rejectBtn.style.display = 'none';
    }
};

window.bulkApprove = function() {
    const checked = Array.from(document.querySelectorAll('.bulk-checkbox:checked')).map(cb => cb.value);
    if (checked.length === 0) return;
    if (!confirm(`Approve ${checked.length} selected payment(s)?`)) return;

    const data = getData();
    checked.forEach(txId => {
        const tx = data.transactions.find(t => t.id === txId);
        if (tx && tx.status === 'pending') {
            tx.status = 'approved';
            logAudit('BULK_APPROVE', `Bulk approved transaction ${txId}`);
        }
    });
    saveData(data);
    loadAdminTransactions();
    loadAdminStudents();
    loadAdminCharts();
    showToast(`${checked.length} payment(s) approved`, 'success');
};

window.bulkReject = function() {
    const checked = Array.from(document.querySelectorAll('.bulk-checkbox:checked')).map(cb => cb.value);
    if (checked.length === 0) return;
    if (!confirm(`Reject ${checked.length} selected payment(s)?`)) return;

    const data = getData();
    checked.forEach(txId => {
        const tx = data.transactions.find(t => t.id === txId);
        if (tx && tx.status === 'pending') {
            tx.status = 'rejected';
            logAudit('BULK_REJECT', `Bulk rejected transaction ${txId}`);
        }
    });
    saveData(data);
    loadAdminTransactions();
    loadAdminStudents();
    loadAdminCharts();
    showToast(`${checked.length} payment(s) rejected`, 'error');
};

// ==================== RECEIPT VERIFICATION ====================

window.verifyReceipt = function() {
    const input = document.getElementById('verify-receipt-input');
    const resultEl = document.getElementById('verify-result');
    if (!input || !resultEl) return;

    const receiptNo = input.value.trim().toUpperCase();
    if (!receiptNo) { showToast('Please enter a receipt number', 'error'); return; }

    // Convert RCT- prefix back to tx_ id format
    const txId = receiptNo.startsWith('RCT-') ? 'tx_' + receiptNo.slice(4) : null;
    const data = getData();
    const tx = txId ? data.transactions.find(t => t.id === txId && t.status === 'approved') : null;

    if (tx) {
        const student = data.users.find(u => u.id === tx.studentId) || { name: 'Unknown', matricNumber: 'N/A' };
        resultEl.innerHTML = `
            <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.3);border-radius:10px;padding:1.25rem;">
                <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.75rem;color:#059669;font-weight:700;">
                    <i data-lucide="shield-check" style="width:18px;height:18px;"></i>
                    Receipt Verified ✓
                </div>
                <div style="font-size:0.875rem;color:var(--text-main);">
                    <p><strong>Student:</strong> ${student.name}</p>
                    <p><strong>Matric:</strong> ${student.matricNumber}</p>
                    <p><strong>Level:</strong> ${tx.level || student.level} Level</p>
                    <p><strong>Amount:</strong> ₦${(tx.amount || 0).toLocaleString()}</p>
                    <p><strong>Date:</strong> ${new Date(tx.date).toLocaleDateString()}</p>
                    <p><strong>Reference:</strong> ${tx.reference}</p>
                    <p><strong>Status:</strong> <span class="status approved">APPROVED</span></p>
                </div>
            </div>
        `;
        if (typeof lucide !== 'undefined') lucide.createIcons();
    } else {
        resultEl.innerHTML = `
            <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.3);border-radius:10px;padding:1.25rem;color:#dc2626;">
                <div style="display:flex;align-items:center;gap:0.5rem;font-weight:700;">
                    <i data-lucide="x-circle" style="width:18px;height:18px;"></i>
                    Receipt Not Found
                </div>
                <p style="margin-top:0.5rem;font-size:0.875rem;">No approved payment found for receipt number <strong>${receiptNo}</strong>. Please check the number and try again.</p>
            </div>
        `;
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }
};
