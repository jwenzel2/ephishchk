<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v ?? '');
$saved = ($_GET['saved'] ?? '') === '1';
$success = $_GET['success'] ?? '';
$error = $_GET['error'] ?? '';
?>
<?php ob_start(); ?>

<div class="preferences-page">
    <h1>My Preferences</h1>
    <p class="subtitle">Manage your account settings and preferences</p>

    <?php if ($saved): ?>
    <div class="alert alert-success">Preferences saved successfully.</div>
    <?php endif; ?>

    <?php if ($success === 'password_changed'): ?>
    <div class="alert alert-success">Password changed successfully.</div>
    <?php endif; ?>

    <?php if ($error): ?>
    <div class="alert alert-error">
        <?php
        $errorMessages = [
            'password_required' => 'All password fields are required.',
            'password_mismatch' => 'New passwords do not match.',
            'password_short' => 'Password must be at least 8 characters.',
            'password_wrong' => 'Current password is incorrect.',
            'email_exists' => 'Email address is already in use by another account.',
        ];
        echo $e($errorMessages[$error] ?? 'An error occurred.');
        ?>
    </div>
    <?php endif; ?>

    <div class="preferences-grid">
        <div class="card">
            <h2>Profile</h2>
            <form method="POST" action="/preferences">
                <?= $csrfField ?>

                <div class="form-group">
                    <label>Username</label>
                    <input type="text" value="<?= $e($currentUser['username'] ?? $currentUser['display_name'] ?? '') ?>" disabled>
                    <small>Username cannot be changed</small>
                </div>

                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email"
                           value="<?= $e($currentUser['email']) ?>">
                    <small>Email can be updated</small>
                </div>

                <div class="form-group">
                    <label>Account Role</label>
                    <input type="text" value="<?= $e(ucfirst($userRole)) ?>" disabled>
                    <small>Your account role is managed by administrators</small>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">Save Profile</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2>Change Password</h2>
            <form method="POST" action="/preferences/password">
                <?= $csrfField ?>

                <div class="form-group">
                    <label for="current_password">Current Password</label>
                    <input type="password" id="current_password" name="current_password" required>
                </div>

                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input type="password" id="new_password" name="new_password" required minlength="8">
                    <small>Minimum 8 characters</small>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">Change Password</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2>Display Preferences</h2>
            <form method="POST" action="/preferences">
                <?= $csrfField ?>

                <div class="form-group">
                    <label for="theme">Theme</label>
                    <select id="theme" name="theme">
                        <option value="light" <?= ($preferences['theme'] ?? 'light') === 'light' ? 'selected' : '' ?>>Light</option>
                        <option value="dark" <?= ($preferences['theme'] ?? '') === 'dark' ? 'selected' : '' ?>>Dark</option>
                        <option value="auto" <?= ($preferences['theme'] ?? '') === 'auto' ? 'selected' : '' ?>>Auto (System)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="results_per_page">Results Per Page</label>
                    <select id="results_per_page" name="results_per_page">
                        <?php foreach ([10, 20, 50, 100] as $count): ?>
                        <option value="<?= $count ?>" <?= ($preferences['results_per_page'] ?? '20') == $count ? 'selected' : '' ?>><?= $count ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="form-group">
                    <label for="time_format">Time Format</label>
                    <select id="time_format" name="time_format">
                        <option value="24h" <?= ($preferences['time_format'] ?? '24h') === '24h' ? 'selected' : '' ?>>24-hour (14:25:14)</option>
                        <option value="12h" <?= ($preferences['time_format'] ?? '24h') === '12h' ? 'selected' : '' ?>>12-hour (2:25:14 PM)</option>
                    </select>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn btn-primary">Save Preferences</button>
                </div>
            </form>
        </div>
    </div>
</div>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
