<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v);

$statusClass = match($scan['status']) {
    'completed' => 'success',
    'failed' => 'error',
    'processing' => 'warning',
    default => 'info'
};

$riskLevel = 'low';
$riskClass = 'success';
if (($scan['risk_score'] ?? 0) >= 50) {
    $riskLevel = 'high';
    $riskClass = 'error';
} elseif (($scan['risk_score'] ?? 0) >= 25) {
    $riskLevel = 'medium';
    $riskClass = 'warning';
}
?>
<?php ob_start(); ?>

<div class="results-page">
    <div class="results-header">
        <h1>Scan Results</h1>
        <a href="/" class="btn btn-secondary">New Scan</a>
    </div>

    <div class="scan-summary card">
        <div class="summary-row">
            <div class="summary-item">
                <span class="label">Input</span>
                <span class="value"><?= $e($scan['input_identifier']) ?></span>
            </div>
            <div class="summary-item">
                <span class="label">Type</span>
                <span class="value badge"><?= $e(ucfirst($scan['scan_type'])) ?> Check</span>
            </div>
            <div class="summary-item">
                <span class="label">Status</span>
                <span class="value badge badge-<?= $statusClass ?>"><?= $e(ucfirst($scan['status'])) ?></span>
            </div>
            <div class="summary-item">
                <span class="label">Date</span>
                <span class="value"><?= $e($scan['created_at']) ?></span>
            </div>
        </div>

        <?php if ($scan['status'] === 'completed'): ?>
        <div class="risk-score-container">
            <div class="risk-score risk-<?= $riskClass ?>">
                <span class="score-value"><?= (int)$scan['risk_score'] ?></span>
                <span class="score-label">Risk Score</span>
            </div>
            <div class="risk-description">
                <span class="risk-level risk-<?= $riskClass ?>"><?= ucfirst($riskLevel) ?> Risk</span>
                <p>
                    <?php if ($riskLevel === 'high'): ?>
                        This email shows significant phishing indicators. Exercise extreme caution.
                    <?php elseif ($riskLevel === 'medium'): ?>
                        Some suspicious indicators detected. Verify the sender before taking action.
                    <?php else: ?>
                        No significant phishing indicators detected.
                    <?php endif; ?>
                </p>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <?php
    // Extract headers from header analysis result
    $extractedHeaders = $resultsByType['header']['details']['extracted_headers'] ?? [];
    if (!empty($extractedHeaders) && $scan['scan_type'] === 'full'):
    ?>
    <div class="email-headers-section card">
        <h2>Email Headers</h2>
        <p class="section-desc">Key headers extracted from the email for phishing detection</p>

        <div class="headers-grid">
            <?php
            // Define which headers to show prominently and their warning conditions
            $headerDisplay = [
                'from' => ['icon' => '👤', 'warn_if_differs_from' => null],
                'reply_to' => ['icon' => '↩️', 'warn_if_differs_from' => 'from'],
                'return_path' => ['icon' => '📮', 'warn_if_differs_from' => 'from'],
                'to' => ['icon' => '📧', 'warn_if_differs_from' => null],
                'subject' => ['icon' => '📝', 'warn_if_differs_from' => null],
                'date' => ['icon' => '📅', 'warn_if_differs_from' => null],
            ];

            foreach ($headerDisplay as $headerKey => $headerConfig):
                if (!isset($extractedHeaders[$headerKey])) continue;
                $header = $extractedHeaders[$headerKey];

                // Check if this header differs from 'from' (potential spoofing indicator)
                $isDifferent = false;
                $fromEmail = strtolower($extractedHeaders['from']['value'] ?? '');
                if ($headerConfig['warn_if_differs_from'] === 'from' && $fromEmail) {
                    $thisEmail = strtolower($header['value'] ?? '');
                    // Extract domains for comparison
                    $fromDomain = explode('@', $fromEmail)[1] ?? '';
                    $thisDomain = explode('@', $thisEmail)[1] ?? '';
                    if ($thisDomain && $fromDomain && $thisDomain !== $fromDomain) {
                        $isDifferent = true;
                    }
                }
            ?>
            <div class="header-item <?= $isDifferent ? 'header-warning' : '' ?>">
                <div class="header-icon"><?= $headerConfig['icon'] ?></div>
                <div class="header-content">
                    <span class="header-label"><?= $e($header['label']) ?></span>
                    <span class="header-value"><?= $e($header['full']) ?></span>
                    <?php if ($isDifferent): ?>
                        <span class="header-alert">Domain differs from sender</span>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>

        <?php
        // Additional headers (collapsible)
        $additionalHeaders = ['message_id', 'x_mailer', 'x_originating_ip', 'authentication_results', 'cc'];
        $hasAdditional = false;
        foreach ($additionalHeaders as $key) {
            if (isset($extractedHeaders[$key])) {
                $hasAdditional = true;
                break;
            }
        }
        if ($hasAdditional):
        ?>
        <details class="additional-headers">
            <summary>Additional Headers</summary>
            <div class="headers-list">
                <?php foreach ($additionalHeaders as $headerKey):
                    if (!isset($extractedHeaders[$headerKey])) continue;
                    $header = $extractedHeaders[$headerKey];
                ?>
                <div class="header-row">
                    <span class="header-label"><?= $e($header['label']) ?>:</span>
                    <span class="header-value"><?= $e($header['value']) ?></span>
                </div>
                <?php endforeach; ?>
            </div>
        </details>
        <?php endif; ?>

        <?php if (!empty($extractedHeaders['received']['hops'])): ?>
        <details class="received-headers">
            <summary>Mail Routing Path (<?= count($extractedHeaders['received']['hops']) ?> hops)</summary>
            <div class="routing-path">
                <?php foreach ($extractedHeaders['received']['hops'] as $i => $hop): ?>
                <div class="hop">
                    <span class="hop-number"><?= $i + 1 ?></span>
                    <code class="hop-content"><?= $e($hop) ?></code>
                </div>
                <?php endforeach; ?>
            </div>
        </details>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <?php
    // Extract all URLs for display
    $allUrls = $resultsByType['links']['details']['links'] ?? [];
    if (!empty($allUrls) && $scan['scan_type'] === 'full'):
        // Get VirusTotal results
        $vtResults = $resultsByType['virustotal_url']['details']['results'] ?? [];
        $vtResultsMap = [];
        foreach ($vtResults as $vt) {
            if (isset($vt['url'])) {
                $vtResultsMap[$vt['url']] = $vt;
            }
        }
    ?>
    <div class="urls-section card">
        <h2>All URLs Found (<?= count($allUrls) ?>)</h2>
        <p class="section-desc">Complete list of URLs extracted from the email body</p>

        <div class="urls-table-container">
            <table class="urls-table">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Domain</th>
                        <th>Risk</th>
                        <th>Flags</th>
                        <th>VirusTotal</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($allUrls as $link):
                        $riskClass = match($link['risk_level'] ?? 'low') {
                            'high' => 'error',
                            'medium' => 'warning',
                            default => 'success'
                        };
                        $flags = [];
                        if (!empty($link['is_shortener'])) $flags[] = 'URL Shortener';
                        if (!empty($link['is_typosquat'])) $flags[] = 'Typosquat';
                        if (!empty($link['is_suspicious_tld'])) $flags[] = 'Suspicious TLD';
                        if (!empty($link['has_ip'])) $flags[] = 'IP Address';
                        if (!empty($link['is_data_uri'])) $flags[] = 'Data URI';
                        if (!empty($link['has_encoded_chars'])) $flags[] = 'Encoded Characters';

                        // Check if URL has VT result
                        $vtResult = $vtResultsMap[$link['url']] ?? null;
                    ?>
                    <tr class="url-row risk-<?= $link['risk_level'] ?? 'low' ?>">
                        <td class="url-cell">
                            <code class="url-text"><?= $e($link['url']) ?></code>
                        </td>
                        <td class="domain-cell"><?= $e($link['domain'] ?? parse_url($link['url'], PHP_URL_HOST) ?? '-') ?></td>
                        <td class="risk-cell">
                            <span class="badge badge-<?= $riskClass ?>"><?= ucfirst($link['risk_level'] ?? 'low') ?></span>
                        </td>
                        <td class="flags-cell">
                            <?php if (!empty($flags)): ?>
                                <?php foreach ($flags as $flag): ?>
                                    <span class="flag-badge"><?= $e($flag) ?></span>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <span class="no-flags">-</span>
                            <?php endif; ?>
                        </td>
                        <td class="vt-scan-cell">
                            <?php if ($vtResult && isset($vtResult['scanned_individually'])): ?>
                                <?php
                                    $malicious = $vtResult['result']['stats']['malicious'] ?? 0;
                                    $suspicious = $vtResult['result']['stats']['suspicious'] ?? 0;
                                    $total = $vtResult['result']['total_vendors'] ?? 0;
                                    $detectionRate = $vtResult['result']['detection_rate'] ?? '0/0';

                                    $vtStatus = 'Clean';
                                    $vtBadgeClass = 'success';
                                    if ($malicious > 0) {
                                        $vtStatus = 'Malicious';
                                        $vtBadgeClass = 'error';
                                    } elseif ($suspicious > 0) {
                                        $vtStatus = 'Suspicious';
                                        $vtBadgeClass = 'warning';
                                    }
                                ?>
                                <div class="vt-result">
                                    <span class="badge badge-<?= $vtBadgeClass ?>"><?= $e($detectionRate) ?></span>
                                    <span class="vt-status"><?= $e($vtStatus) ?></span>
                                </div>
                            <?php else: ?>
                                <button class="btn btn-sm btn-vt-scan"
                                        data-scan-id="<?= $scan['id'] ?>"
                                        data-url="<?= $e($link['url']) ?>"
                                        onclick="scanUrlWithVirusTotal(this)">
                                    Scan with VT
                                </button>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>

    <div class="results-grid">
        <?php
        $checkTypes = [
            'spf' => ['icon' => 'SPF', 'title' => 'SPF Check'],
            'dkim' => ['icon' => 'DKIM', 'title' => 'DKIM Check'],
            'dmarc' => ['icon' => 'DMARC', 'title' => 'DMARC Check'],
            'header' => ['icon' => 'HDR', 'title' => 'Header Analysis'],
            'links' => ['icon' => 'URL', 'title' => 'Link Analysis'],
            'attachments' => ['icon' => 'ATT', 'title' => 'Attachment Analysis'],
            'virustotal_url' => ['icon' => 'VT', 'title' => 'VirusTotal URL Scan'],
            'virustotal_file' => ['icon' => 'VT', 'title' => 'VirusTotal File Scan'],
        ];

        foreach ($checkTypes as $type => $info):
            if (!isset($resultsByType[$type])) continue;
            $result = $resultsByType[$type];
            $resultClass = match($result['status']) {
                'pass' => 'success',
                'fail' => 'error',
                'warning' => 'warning',
                default => 'info'
            };
        ?>
        <div class="result-card card">
            <div class="result-header">
                <span class="result-icon <?= $resultClass ?>"><?= $info['icon'] ?></span>
                <div class="result-title">
                    <h3><?= $e($info['title']) ?></h3>
                    <span class="badge badge-<?= $resultClass ?>"><?= $e(ucfirst($result['status'])) ?></span>
                </div>
            </div>
            <div class="result-body">
                <p class="result-summary"><?= $e($result['summary']) ?></p>

                <?php if (!empty($result['details'])): ?>
                <details class="result-details">
                    <summary>View Details</summary>
                    <div class="details-content">
                        <?php
                        $details = $result['details'];

                        // SPF/DKIM/DMARC record display
                        if (isset($details['record'])): ?>
                            <div class="detail-item">
                                <strong>Record:</strong>
                                <code><?= $e($details['record']) ?></code>
                            </div>
                        <?php endif;

                        // Issues display
                        if (!empty($details['issues']['errors'])): ?>
                            <div class="detail-item errors">
                                <strong>Errors:</strong>
                                <ul>
                                    <?php foreach ($details['issues']['errors'] as $error): ?>
                                        <li><?= $e($error) ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif;

                        if (!empty($details['issues']['warnings'])): ?>
                            <div class="detail-item warnings">
                                <strong>Warnings:</strong>
                                <ul>
                                    <?php foreach ($details['issues']['warnings'] as $warning): ?>
                                        <li><?= $e($warning) ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif;

                        if (!empty($details['issues']['info'])): ?>
                            <div class="detail-item info">
                                <strong>Info:</strong>
                                <ul>
                                    <?php foreach ($details['issues']['info'] as $info): ?>
                                        <li><?= $e($info) ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif;

                        // Header findings
                        if (!empty($details['findings'])): ?>
                            <div class="detail-item">
                                <strong>Findings:</strong>
                                <ul>
                                    <?php foreach ($details['findings'] as $finding): ?>
                                        <li class="finding finding-<?= $e($finding['severity']) ?>">
                                            <span class="finding-type"><?= $e($finding['type']) ?></span>
                                            <?= $e($finding['message']) ?>
                                            <?php if (!empty($finding['details'])): ?>
                                                <br><small><?= $e($finding['details']) ?></small>
                                            <?php endif; ?>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif;

                        // Links display
                        if (!empty($details['links'])): ?>
                            <div class="detail-item">
                                <strong>Links Found (<?= count($details['links']) ?>):</strong>
                                <ul class="links-list">
                                    <?php foreach (array_slice($details['links'], 0, 10) as $link): ?>
                                        <li class="link-item risk-<?= $e($link['risk_level'] ?? 'low') ?>">
                                            <span class="link-url"><?= $e($link['url']) ?></span>
                                            <span class="link-score">Score: <?= (int)$link['score'] ?></span>
                                        </li>
                                    <?php endforeach; ?>
                                    <?php if (count($details['links']) > 10): ?>
                                        <li><em>... and <?= count($details['links']) - 10 ?> more</em></li>
                                    <?php endif; ?>
                                </ul>
                            </div>
                        <?php endif;

                        // Attachments display
                        if (!empty($details['attachments'])): ?>
                            <div class="detail-item">
                                <strong>Attachments:</strong>
                                <ul class="attachments-list">
                                    <?php foreach ($details['attachments'] as $att): ?>
                                        <li class="attachment-item risk-<?= $e($att['risk_level']) ?>">
                                            <span class="att-name"><?= $e($att['filename']) ?></span>
                                            <span class="att-type"><?= $e($att['content_type']) ?></span>
                                            <span class="att-risk"><?= ucfirst($e($att['risk_level'])) ?> risk</span>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif;

                        // DKIM selectors
                        if (!empty($details['selectors'])): ?>
                            <div class="detail-item">
                                <strong>DKIM Selectors Found:</strong>
                                <ul>
                                    <?php foreach ($details['selectors'] as $selector => $data): ?>
                                        <li>
                                            <strong><?= $e($selector) ?></strong>
                                            <?php if (!empty($data['validation']['errors'])): ?>
                                                <span class="badge badge-error">Errors</span>
                                            <?php elseif (!empty($data['validation']['warnings'])): ?>
                                                <span class="badge badge-warning">Warnings</span>
                                            <?php else: ?>
                                                <span class="badge badge-success">Valid</span>
                                            <?php endif; ?>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif;

                        // Recommendation
                        if (!empty($details['recommendation'])): ?>
                            <div class="detail-item recommendation">
                                <strong>Recommendation:</strong>
                                <p><?= $e($details['recommendation']) ?></p>
                            </div>
                        <?php endif; ?>
                    </div>
                </details>
                <?php endif; ?>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
</div>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
