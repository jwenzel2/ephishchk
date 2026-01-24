<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= $csrfToken ?? '' ?>">
    <title><?= $e($title ?? 'ephishchk') ?> - Email Phishing Checker</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <a href="/" class="logo">ephishchk</a>
            <ul class="nav-links">
                <li><a href="/" class="<?= ($_SERVER['REQUEST_URI'] ?? '') === '/' ? 'active' : '' ?>">Scan</a></li>
                <?php if (!empty($currentUser)): ?>
                <li><a href="/history" class="<?= str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/history') ? 'active' : '' ?>">History</a></li>
                <li><a href="/preferences" class="<?= str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/preferences') ? 'active' : '' ?>">Preferences</a></li>
                <?php if (($currentUser['role'] ?? 'user') === 'admin'): ?>
                <li><a href="/settings" class="<?= str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/settings') ? 'active' : '' ?>">Settings</a></li>
                <li><a href="/admin/users" class="<?= str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/admin') ? 'active' : '' ?>">Users</a></li>
                <?php endif; ?>
                <?php endif; ?>
            </ul>
            <div class="nav-auth">
                <?php if (!empty($currentUser)): ?>
                <span class="user-name">
                    <?= $e($currentUser['display_name'] ?? $currentUser['email']) ?>
                    <?php if (($currentUser['role'] ?? 'user') === 'admin'): ?>
                    <span class="role-badge">Admin</span>
                    <?php endif; ?>
                </span>
                <form method="POST" action="/logout" class="logout-form">
                    <input type="hidden" name="_csrf_token" value="<?= $csrfToken ?? '' ?>">
                    <button type="submit" class="btn btn-secondary btn-small">Logout</button>
                </form>
                <?php else: ?>
                <a href="/login" class="btn btn-secondary btn-small">Login</a>
                <a href="/register" class="btn btn-primary btn-small">Register</a>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <main class="container">
        <?php if (!empty($error)): ?>
            <div class="alert alert-error">
                <?= $e($error) ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($success)): ?>
            <div class="alert alert-success">
                <?= $e($success) ?>
            </div>
        <?php endif; ?>

        <?= $content ?? '' ?>
    </main>

    <footer class="footer">
        <div class="container">
            <p>ephishchk - Email Phishing Checker</p>
        </div>
    </footer>

    <script src="/assets/js/app.js"></script>
</body>
</html>
