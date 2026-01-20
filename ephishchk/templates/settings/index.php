<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v);

$saved = isset($_GET['saved']);
?>
<?php ob_start(); ?>

<div class="settings-page">
    <h1>Settings</h1>

    <?php if ($saved): ?>
        <div class="alert alert-success">Settings saved successfully.</div>
    <?php endif; ?>

    <form method="POST" action="/settings" class="settings-form">
        <?= $csrfField ?>

        <div class="card">
            <h2>VirusTotal Integration</h2>
            <p class="card-description">Configure VirusTotal API for file and URL scanning.</p>

            <div class="form-group">
                <label for="virustotal_api_key">API Key</label>
                <input type="password" id="virustotal_api_key" name="virustotal_api_key"
                       placeholder="<?= $vtConfigured ? '••••••••••••••••' : 'Enter your VirusTotal API key' ?>">
                <small>Get a free API key at <a href="https://www.virustotal.com/gui/join-us" target="_blank">virustotal.com</a></small>
            </div>

            <div class="form-group">
                <label for="virustotal_tier">API Tier</label>
                <select id="virustotal_tier" name="virustotal_tier">
                    <option value="free" <?= ($settings['virustotal_tier']['value'] ?? 'free') === 'free' ? 'selected' : '' ?>>
                        Free (4 req/min, 500/day)
                    </option>
                    <option value="premium" <?= ($settings['virustotal_tier']['value'] ?? '') === 'premium' ? 'selected' : '' ?>>
                        Premium (30 req/min, 10000/day)
                    </option>
                </select>
            </div>

            <?php if ($vtConfigured && $vtStatus): ?>
            <div class="vt-status">
                <h4>Current Usage</h4>
                <div class="status-grid">
                    <div class="status-item">
                        <span class="label">Per Minute</span>
                        <span class="value"><?= $vtStatus['minute']['used'] ?> / <?= $vtStatus['minute']['limit'] ?></span>
                    </div>
                    <div class="status-item">
                        <span class="label">Per Day</span>
                        <span class="value"><?= $vtStatus['day']['used'] ?> / <?= $vtStatus['day']['limit'] ?></span>
                    </div>
                </div>
                <button type="button" id="test-vt" class="btn btn-secondary">Test Connection</button>
                <span id="test-result"></span>
            </div>
            <?php endif; ?>

            <div class="form-group checkbox-group">
                <label>
                    <input type="checkbox" name="enable_vt_file_scan" value="1"
                           <?= ($settings['enable_vt_file_scan']['value'] ?? true) ? 'checked' : '' ?>>
                    Enable file scanning for attachments
                </label>
            </div>

            <div class="form-group checkbox-group">
                <label>
                    <input type="checkbox" name="enable_vt_url_scan" value="1"
                           <?= ($settings['enable_vt_url_scan']['value'] ?? true) ? 'checked' : '' ?>>
                    Enable URL scanning for links
                </label>
            </div>
        </div>

        <div class="card">
            <h2>Scan Settings</h2>

            <div class="form-group">
                <label for="scan_retention_days">Scan History Retention (days)</label>
                <input type="number" id="scan_retention_days" name="scan_retention_days"
                       value="<?= (int)($settings['scan_retention_days']['value'] ?? 30) ?>"
                       min="1" max="365">
                <small>How long to keep scan history</small>
            </div>

            <div class="form-group">
                <label for="max_links_per_scan">Maximum Links Per Scan</label>
                <input type="number" id="max_links_per_scan" name="max_links_per_scan"
                       value="<?= (int)($settings['max_links_per_scan']['value'] ?? 50) ?>"
                       min="10" max="200">
                <small>Limit number of links analyzed per email</small>
            </div>
        </div>

        <div class="form-actions">
            <button type="submit" class="btn btn-primary">Save Settings</button>
        </div>
    </form>
</div>

<script>
document.getElementById('test-vt')?.addEventListener('click', async function() {
    const result = document.getElementById('test-result');
    result.textContent = 'Testing...';
    result.className = '';

    try {
        const response = await fetch('/settings/test-virustotal', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: '_csrf_token=' + encodeURIComponent(document.querySelector('[name="_csrf_token"]').value)
        });
        const data = await response.json();

        if (data.success) {
            result.textContent = 'Connection successful!';
            result.className = 'success';
        } else {
            result.textContent = 'Failed: ' + (data.error || 'Unknown error');
            result.className = 'error';
        }
    } catch (e) {
        result.textContent = 'Error: ' + e.message;
        result.className = 'error';
    }
});
</script>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
