<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v ?? '');
?>
<?php ob_start(); ?>

<div class="auth-page">
    <div class="auth-card card">
        <h1>Register</h1>
        <p class="card-description">Create an account to save and track your scan results.</p>

        <form method="POST" action="/register" class="auth-form">
            <?= $csrfField ?>

            <div class="form-group">
                <label for="email">Email Address</label>
                <input
                    type="email"
                    id="email"
                    name="email"
                    value="<?= $e($email ?? '') ?>"
                    required
                    autofocus
                    autocomplete="email"
                >
            </div>

            <div class="form-group">
                <label for="display_name">Display Name (optional)</label>
                <input
                    type="text"
                    id="display_name"
                    name="display_name"
                    value="<?= $e($displayName ?? '') ?>"
                    autocomplete="name"
                >
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    required
                    minlength="8"
                    autocomplete="new-password"
                >
                <small>Must be at least 8 characters long</small>
            </div>

            <div class="form-group">
                <label for="password_confirm">Confirm Password</label>
                <input
                    type="password"
                    id="password_confirm"
                    name="password_confirm"
                    required
                    autocomplete="new-password"
                >
            </div>

            <div class="form-actions">
                <button type="submit" class="btn btn-primary btn-block">Create Account</button>
            </div>
        </form>

        <div class="auth-links">
            <p>Already have an account? <a href="/login">Login</a></p>
        </div>
    </div>
</div>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
