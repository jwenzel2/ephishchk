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
            <h2>Server Settings</h2>
            <p class="card-description">Configure server-wide settings.</p>

            <div class="form-group">
                <label for="timezone">Timezone</label>
                <select id="timezone" name="timezone">
                    <?php
                    $currentTz = $settings['timezone']['value'] ?? 'UTC';
                    $timezones = [
                        'UTC' => 'UTC — Coordinated Universal Time',

                        // North America - United States
                        'America/New_York' => 'US Eastern (New York, Detroit, Atlanta)',
                        'America/Chicago' => 'US Central (Chicago, Houston, Dallas)',
                        'America/Indiana/Indianapolis' => 'US Eastern (Indianapolis)',
                        'America/Indiana/Knox' => 'US Central (Knox, Indiana)',
                        'America/Detroit' => 'US Eastern (Detroit)',
                        'America/Kentucky/Louisville' => 'US Eastern (Louisville)',
                        'America/Kentucky/Monticello' => 'US Eastern (Monticello)',
                        'America/Denver' => 'US Mountain (Denver, Salt Lake City)',
                        'America/Phoenix' => 'US Mountain (Phoenix - No DST)',
                        'America/Los_Angeles' => 'US Pacific (Los Angeles, Seattle)',
                        'America/Anchorage' => 'US Alaska (Anchorage)',
                        'Pacific/Honolulu' => 'US Hawaii (Honolulu)',
                        'America/Boise' => 'US Mountain (Boise)',
                        'America/North_Dakota/Center' => 'US Central (North Dakota - Center)',
                        'America/North_Dakota/New_Salem' => 'US Central (North Dakota - New Salem)',
                        'America/North_Dakota/Beulah' => 'US Central (North Dakota - Beulah)',

                        // North America - Canada
                        'America/Toronto' => 'Canada Eastern (Toronto)',
                        'America/Vancouver' => 'Canada Pacific (Vancouver)',
                        'America/Halifax' => 'Canada Atlantic (Halifax)',
                        'America/Winnipeg' => 'Canada Central (Winnipeg)',
                        'America/Edmonton' => 'Canada Mountain (Edmonton)',
                        'America/Regina' => 'Canada Central (Regina - No DST)',
                        'America/St_Johns' => 'Canada Newfoundland (St. Johns)',

                        // North America - Mexico
                        'America/Mexico_City' => 'Mexico (Mexico City)',
                        'America/Cancun' => 'Mexico (Cancun)',
                        'America/Tijuana' => 'Mexico (Tijuana)',

                        // Central & South America
                        'America/Bogota' => 'Colombia (Bogota)',
                        'America/Lima' => 'Peru (Lima)',
                        'America/Santiago' => 'Chile (Santiago)',
                        'America/Buenos_Aires' => 'Argentina (Buenos Aires)',
                        'America/Sao_Paulo' => 'Brazil (São Paulo)',
                        'America/Caracas' => 'Venezuela (Caracas)',

                        // Europe
                        'Europe/London' => 'UK (London)',
                        'Europe/Dublin' => 'Ireland (Dublin)',
                        'Europe/Paris' => 'France (Paris)',
                        'Europe/Berlin' => 'Germany (Berlin)',
                        'Europe/Madrid' => 'Spain (Madrid)',
                        'Europe/Rome' => 'Italy (Rome)',
                        'Europe/Amsterdam' => 'Netherlands (Amsterdam)',
                        'Europe/Brussels' => 'Belgium (Brussels)',
                        'Europe/Vienna' => 'Austria (Vienna)',
                        'Europe/Warsaw' => 'Poland (Warsaw)',
                        'Europe/Prague' => 'Czech Republic (Prague)',
                        'Europe/Budapest' => 'Hungary (Budapest)',
                        'Europe/Athens' => 'Greece (Athens)',
                        'Europe/Stockholm' => 'Sweden (Stockholm)',
                        'Europe/Oslo' => 'Norway (Oslo)',
                        'Europe/Copenhagen' => 'Denmark (Copenhagen)',
                        'Europe/Helsinki' => 'Finland (Helsinki)',
                        'Europe/Zurich' => 'Switzerland (Zurich)',
                        'Europe/Lisbon' => 'Portugal (Lisbon)',
                        'Europe/Moscow' => 'Russia (Moscow)',
                        'Europe/Istanbul' => 'Turkey (Istanbul)',

                        // Asia - Middle East
                        'Asia/Dubai' => 'UAE (Dubai)',
                        'Asia/Jerusalem' => 'Israel (Jerusalem)',
                        'Asia/Riyadh' => 'Saudi Arabia (Riyadh)',
                        'Asia/Tehran' => 'Iran (Tehran)',

                        // Asia - Central & South
                        'Asia/Kolkata' => 'India (Kolkata/Mumbai/Delhi)',
                        'Asia/Karachi' => 'Pakistan (Karachi)',
                        'Asia/Dhaka' => 'Bangladesh (Dhaka)',
                        'Asia/Kathmandu' => 'Nepal (Kathmandu)',
                        'Asia/Colombo' => 'Sri Lanka (Colombo)',

                        // Asia - East & Southeast
                        'Asia/Shanghai' => 'China (Beijing/Shanghai)',
                        'Asia/Hong_Kong' => 'Hong Kong',
                        'Asia/Tokyo' => 'Japan (Tokyo)',
                        'Asia/Seoul' => 'South Korea (Seoul)',
                        'Asia/Singapore' => 'Singapore',
                        'Asia/Bangkok' => 'Thailand (Bangkok)',
                        'Asia/Jakarta' => 'Indonesia (Jakarta)',
                        'Asia/Manila' => 'Philippines (Manila)',
                        'Asia/Kuala_Lumpur' => 'Malaysia (Kuala Lumpur)',
                        'Asia/Ho_Chi_Minh' => 'Vietnam (Ho Chi Minh)',
                        'Asia/Taipei' => 'Taiwan (Taipei)',

                        // Pacific
                        'Australia/Sydney' => 'Australia (Sydney)',
                        'Australia/Melbourne' => 'Australia (Melbourne)',
                        'Australia/Brisbane' => 'Australia (Brisbane)',
                        'Australia/Perth' => 'Australia (Perth)',
                        'Australia/Adelaide' => 'Australia (Adelaide)',
                        'Pacific/Auckland' => 'New Zealand (Auckland)',
                        'Pacific/Fiji' => 'Fiji',
                        'Pacific/Guam' => 'Guam',

                        // Africa
                        'Africa/Cairo' => 'Egypt (Cairo)',
                        'Africa/Johannesburg' => 'South Africa (Johannesburg)',
                        'Africa/Lagos' => 'Nigeria (Lagos)',
                        'Africa/Nairobi' => 'Kenya (Nairobi)',
                        'Africa/Casablanca' => 'Morocco (Casablanca)',
                        'Africa/Algiers' => 'Algeria (Algiers)',
                    ];

                    foreach ($timezones as $tz => $label):
                    ?>
                    <option value="<?= $tz ?>" <?= $currentTz === $tz ? 'selected' : '' ?>><?= $e($label) ?></option>
                    <?php endforeach; ?>
                </select>
                <small>Server timezone for displaying dates and times. Current time: <?= date('g:i A T') ?></small>
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
