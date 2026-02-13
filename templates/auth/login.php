<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v ?? '');
?>
<?php ob_start(); ?>

<div class="auth-page">
    <div class="auth-card card">
        <h1>Login</h1>
        <p class="card-description">Sign in to your account to save and view your scan results.</p>

        <form method="POST" action="/login" class="auth-form">
            <?= $csrfField ?>

            <div class="form-group">
                <label for="username">Username</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    value="<?= $e($username ?? '') ?>"
                    required
                    autofocus
                    autocomplete="username"
                >
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    required
                    autocomplete="current-password"
                >
            </div>

            <div class="form-actions">
                <button type="submit" class="btn btn-primary btn-block">Login</button>
            </div>
        </form>

        <div class="auth-links">
            <p>Don't have an account? <a href="/register">Register</a></p>
        </div>
    </div>
</div>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
