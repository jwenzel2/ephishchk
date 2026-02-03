<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v);
?>
<?php ob_start(); ?>

<div class="history-page">
    <h1>Scan History</h1>

    <?php if (empty($scans)): ?>
        <div class="card empty-state">
            <p>No scans yet. <a href="/">Run your first scan</a></p>
        </div>
    <?php else: ?>
        <div class="card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Input</th>
                        <th>Status</th>
                        <th>Risk</th>
                        <th>Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($scans as $scan):
                        $statusClass = match($scan['status']) {
                            'completed' => 'success',
                            'failed' => 'error',
                            'processing' => 'warning',
                            default => 'info'
                        };

                        $riskClass = 'success';
                        if (($scan['risk_score'] ?? 0) >= 50) {
                            $riskClass = 'error';
                        } elseif (($scan['risk_score'] ?? 0) >= 25) {
                            $riskClass = 'warning';
                        }
                    ?>
                    <tr>
                        <td><?= (int)$scan['id'] ?></td>
                        <td><span class="badge"><?= $e(ucfirst($scan['scan_type'])) ?></span></td>
                        <td class="input-cell" title="<?= $e($scan['input_identifier']) ?>">
                            <?= $e(substr($scan['input_identifier'], 0, 40)) ?>
                            <?= strlen($scan['input_identifier']) > 40 ? '...' : '' ?>
                        </td>
                        <td><span class="badge badge-<?= $statusClass ?>"><?= $e(ucfirst($scan['status'])) ?></span></td>
                        <td>
                            <?php if ($scan['risk_score'] !== null): ?>
                                <span class="badge badge-<?= $riskClass ?>"><?= (int)$scan['risk_score'] ?></span>
                            <?php else: ?>
                                <span class="badge">-</span>
                            <?php endif; ?>
                        </td>
                        <td><?= $e(date(($userPreferences['time_format'] ?? '24h') === '12h' ? 'Y-m-d g:i:s A' : 'Y-m-d H:i:s', strtotime($scan['created_at']))) ?></td>
                        <td class="actions-cell">
                            <a href="/scan/<?= (int)$scan['id'] ?>" class="btn btn-small">View</a>
                            <form method="POST" action="/history/<?= (int)$scan['id'] ?>/delete" class="inline-form" onsubmit="return confirm('Delete this scan?')">
                                <?= $csrfField ?>
                                <button type="submit" class="btn btn-small btn-danger">Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php if ($totalPages > 1): ?>
        <div class="pagination">
            <?php if ($page > 1): ?>
                <a href="/history?page=<?= $page - 1 ?>" class="btn btn-small">&laquo; Previous</a>
            <?php endif; ?>

            <span class="page-info">Page <?= $page ?> of <?= $totalPages ?></span>

            <?php if ($page < $totalPages): ?>
                <a href="/history?page=<?= $page + 1 ?>" class="btn btn-small">Next &raquo;</a>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
