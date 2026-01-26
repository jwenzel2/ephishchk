<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v ?? '');
?>
<?php ob_start(); ?>

<div class="admin-page">
    <h1>Safe Domains Management</h1>
    <p class="subtitle">Manage trusted domains for typosquatting detection</p>

    <!-- Information Card -->
    <div class="card info-card">
        <h3>How Typosquatting Detection Works</h3>
        <p>Safe domains are used to detect potential typosquatting attempts in scanned emails. When a URL is found that closely resembles a safe domain, it's flagged as a potential security risk.</p>

        <div class="detection-methods">
            <div class="method">
                <strong>Levenshtein Distance:</strong>
                <p>Detects domains with 1-2 character differences from trusted domains.</p>
                <code>google.com → g00gle.com (flagged)</code>
            </div>
            <div class="method">
                <strong>Character Substitution:</strong>
                <p>Identifies l33t speak and similar character replacements.</p>
                <code>paypal.com → paypa1.com (flagged)</code>
            </div>
            <div class="method">
                <strong>Homograph Attacks:</strong>
                <p>Detects punycode domains that visually mimic trusted domains.</p>
                <code>xn--pple.com → apple lookalike (flagged)</code>
            </div>
        </div>
    </div>

    <!-- Add Domain Form -->
    <div class="card">
        <h2>Add New Safe Domain</h2>
        <form method="POST" action="/admin/safe-domains/add" class="safe-domain-form">
            <?= $csrfField ?>
            <div class="form-group">
                <label for="domain">Domain</label>
                <input type="text"
                       id="domain"
                       name="domain"
                       placeholder="example.com"
                       required
                       pattern="^[a-zA-Z0-9][a-zA-Z0-9-_.]*\.[a-zA-Z]{2,}$">
                <small class="form-help">Enter domain name only (e.g., "example.com", not "https://example.com")</small>
            </div>
            <div class="form-group">
                <label for="notes">Notes (Optional)</label>
                <input type="text"
                       id="notes"
                       name="notes"
                       placeholder="e.g., Company website, Payment processor">
            </div>
            <button type="submit" class="btn btn-primary">Add Domain</button>
        </form>
    </div>

    <!-- Safe Domains List -->
    <div class="card">
        <h2>Safe Domains List (<?= $total ?>)</h2>

        <?php if (empty($domains)): ?>
        <p class="no-data">No safe domains configured yet.</p>
        <?php else: ?>
        <div class="table-responsive">
            <table class="data-table safe-domains-table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Added By</th>
                        <th>Date Added</th>
                        <th>Notes</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($domains as $domain): ?>
                    <tr data-domain-id="<?= $domain['id'] ?>">
                        <td>
                            <code class="domain-code"><?= $e($domain['domain']) ?></code>
                        </td>
                        <td><?= $e($domain['added_by_email'] ?? 'System') ?></td>
                        <td><?= $e(date('M j, Y', strtotime($domain['created_at']))) ?></td>
                        <td><?= $e($domain['notes'] ?? '-') ?></td>
                        <td class="actions">
                            <form method="POST"
                                  action="/admin/safe-domains/delete"
                                  class="inline-form"
                                  onsubmit="return confirm('Are you sure you want to remove <?= $e($domain['domain']) ?> from the safe domains list?');">
                                <?= $csrfField ?>
                                <input type="hidden" name="id" value="<?= $domain['id'] ?>">
                                <button type="submit" class="btn btn-small btn-danger">Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </div>

    <!-- Quick Guide -->
    <div class="card help-card">
        <h3>Adding Domains from Scan Results</h3>
        <p>When viewing scan results, admins can quickly add domains to the safe list:</p>
        <ol>
            <li>Navigate to any scan result with URLs</li>
            <li>Click the <strong>"+ Safe"</strong> button next to any URL</li>
            <li>The domain will be automatically added to this list</li>
            <li>Future scans will use this domain for typosquatting detection</li>
        </ol>
    </div>
</div>

<script>
// Auto-focus on domain input
document.addEventListener('DOMContentLoaded', function() {
    const domainInput = document.getElementById('domain');
    if (domainInput) {
        domainInput.focus();
    }

    // Normalize domain input on blur (remove protocol, www, etc.)
    domainInput.addEventListener('blur', function() {
        let value = this.value.trim();

        // Remove protocol
        value = value.replace(/^https?:\/\//i, '');

        // Remove www.
        value = value.replace(/^www\./i, '');

        // Remove trailing slash
        value = value.replace(/\/$/, '');

        // Remove path
        value = value.replace(/\/.*$/, '');

        this.value = value.toLowerCase();
    });
});
</script>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
