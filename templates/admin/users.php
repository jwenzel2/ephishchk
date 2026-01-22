<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v ?? '');
?>
<?php ob_start(); ?>

<div class="admin-page">
    <h1>User Management</h1>
    <p class="subtitle">Manage registered users and their roles</p>

    <div class="card">
        <div class="table-responsive">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Display Name</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                    <tr data-user-id="<?= $user['id'] ?>">
                        <td><?= $e($user['email']) ?></td>
                        <td><?= $e($user['display_name'] ?? '-') ?></td>
                        <td>
                            <span class="badge badge-<?= $user['role'] === 'admin' ? 'admin' : 'user' ?>">
                                <?= $e(ucfirst($user['role'])) ?>
                            </span>
                        </td>
                        <td>
                            <span class="badge badge-<?= $user['is_active'] ? 'active' : 'inactive' ?>">
                                <?= $user['is_active'] ? 'Active' : 'Inactive' ?>
                            </span>
                        </td>
                        <td><?= $e(date('M j, Y', strtotime($user['created_at']))) ?></td>
                        <td><?= $user['last_login_at'] ? $e(date('M j, Y g:i A', strtotime($user['last_login_at']))) : 'Never' ?></td>
                        <td class="actions">
                            <?php if ($user['id'] !== $currentUser['id']): ?>
                            <form method="POST" action="/admin/users/role" class="inline-form">
                                <?= $csrfField ?>
                                <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                <select name="role" onchange="this.form.submit()" class="role-select">
                                    <option value="user" <?= $user['role'] === 'user' ? 'selected' : '' ?>>User</option>
                                    <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                                </select>
                            </form>
                            <form method="POST" action="/admin/users/toggle-active" class="inline-form">
                                <?= $csrfField ?>
                                <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                                <button type="submit" class="btn btn-small btn-<?= $user['is_active'] ? 'warning' : 'success' ?>">
                                    <?= $user['is_active'] ? 'Deactivate' : 'Activate' ?>
                                </button>
                            </form>
                            <?php else: ?>
                            <span class="text-muted">(You)</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php if ($totalPages > 1): ?>
        <div class="pagination">
            <?php if ($page > 1): ?>
            <a href="/admin/users?page=<?= $page - 1 ?>" class="btn btn-secondary btn-small">Previous</a>
            <?php endif; ?>

            <span class="pagination-info">Page <?= $page ?> of <?= $totalPages ?> (<?= $total ?> users)</span>

            <?php if ($page < $totalPages): ?>
            <a href="/admin/users?page=<?= $page + 1 ?>" class="btn btn-secondary btn-small">Next</a>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>
</div>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
