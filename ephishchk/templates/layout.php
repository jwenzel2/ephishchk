<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $e($title ?? 'ephishchk') ?> - Email Phishing Checker</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <a href="/" class="logo">ephishchk</a>
            <ul class="nav-links">
                <li><a href="/" class="<?= ($_SERVER['REQUEST_URI'] ?? '') === '/' ? 'active' : '' ?>">Scan</a></li>
                <li><a href="/history" class="<?= str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/history') ? 'active' : '' ?>">History</a></li>
                <li><a href="/settings" class="<?= str_starts_with($_SERVER['REQUEST_URI'] ?? '', '/settings') ? 'active' : '' ?>">Settings</a></li>
            </ul>
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
