<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v);

$statusClass = match($scan['status']) {
    'completed' => 'success',
    'failed' => 'error',
    'processing' => 'warning',
    default => 'info'
};

$statusText = match($scan['status']) {
    'completed' => 'Completed',
    'failed' => 'Failed',
    'processing' => 'Processing',
    default => ucfirst($scan['status'])
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
                <span class="value badge badge-<?= $statusClass ?>"><?= $e($statusText) ?></span>
            </div>
            <div class="summary-item">
                <span class="label">Date</span>
                <span class="value"><?= $e(date(($userPreferences['time_format'] ?? '24h') === '12h' ? 'Y-m-d g:i:s A' : 'Y-m-d H:i:s', strtotime($scan['created_at']))) ?></span>
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
    // Check for malicious domain matches (confirmed phish)
    $maliciousDomainFindings = [];
    foreach ($resultsByType as $type => $result) {
        if (!empty($result['details']['findings'])) {
            foreach ($result['details']['findings'] as $finding) {
                if (($finding['type'] ?? '') === 'malicious_domain_match') {
                    $maliciousDomainFindings[] = $finding;
                }
            }
        }
    }
    // Also check links for malicious domain matches
    if (!empty($resultsByType['links']['details']['links'])) {
        foreach ($resultsByType['links']['details']['links'] as $link) {
            if (!empty($link['findings'])) {
                foreach ($link['findings'] as $finding) {
                    if (($finding['type'] ?? '') === 'malicious_domain_match') {
                        $maliciousDomainFindings[] = $finding;
                    }
                }
            }
        }
    }
    if (!empty($maliciousDomainFindings)):
    ?>
    <div class="card" style="border-left: 4px solid var(--color-error, #dc3545); background: rgba(220, 53, 69, 0.08);">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
            <span style="font-size: 1.5em;">&#9888;</span>
            <h2 style="margin: 0; color: var(--color-error, #dc3545);">Confirmed Phish</h2>
        </div>
        <p style="margin: 0 0 8px 0;">This email contains domains that match known malicious domains:</p>
        <ul style="margin: 0; padding-left: 20px;">
            <?php foreach ($maliciousDomainFindings as $mf): ?>
            <li><strong><?= $e($mf['matched_malicious_domain'] ?? '') ?></strong> &mdash; <?= $e($mf['message'] ?? '') ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php endif; ?>

    <?php
    // Extract headers from header analysis result
    $extractedHeaders = $resultsByType['header']['details']['extracted_headers'] ?? [];

    // Extract typosquatting findings from header analysis
    $headerTyposquattingFindings = [];
    $headerMaliciousFindings = [];
    if (isset($resultsByType['header']['details']['findings'])) {
        foreach ($resultsByType['header']['details']['findings'] as $finding) {
            if (isset($finding['header_field']) && $finding['type'] === 'typosquatting_safe_domain') {
                $headerTyposquattingFindings[$finding['header_field']] = $finding;
            }
            if (isset($finding['header_field']) && $finding['type'] === 'malicious_domain_match') {
                $headerMaliciousFindings[$finding['header_field']] = $finding;
            }
        }
    }

    if (!empty($extractedHeaders) && $scan['scan_type'] === 'full'):
    ?>
    <div class="email-headers-section card">
        <h2>Email Headers</h2>
        <p class="section-desc">Key headers extracted from the email for phishing detection</p>

        <?php
        // Display Authentication status if available
        $authStatus = $resultsByType['header']['details']['auth_status'] ?? null;
        if ($authStatus):
            $authClass = match($authStatus['status']) {
                'pass' => 'auth-pass',
                'fail' => 'auth-fail',
                'partial' => 'auth-partial',
                default => 'auth-none'
            };
            $authIcon = match($authStatus['status']) {
                'pass' => '✓',
                'fail' => '✗',
                'partial' => '⚠',
                default => '?'
            };
        ?>
        <div class="authentication-status <?= $authClass ?>">
            <div class="auth-header">
                <span class="auth-icon"><?= $authIcon ?></span>
                <span class="auth-label">Authentication:</span>
                <span class="auth-message"><?= $e($authStatus['message']) ?></span>
            </div>
            <div class="auth-details">
                <?php if ($authStatus['spf'] !== null): ?>
                    <span class="auth-detail">
                        <strong>SPF:</strong> <?= $e(strtoupper($authStatus['spf'])) ?>
                    </span>
                <?php endif; ?>
                <?php if ($authStatus['dkim'] !== null): ?>
                    <span class="auth-detail">
                        <strong>DKIM:</strong> <?= $e(strtoupper($authStatus['dkim'])) ?>
                    </span>
                <?php endif; ?>
                <span class="auth-detail">
                    <strong>DMARC:</strong> <?= $e(strtoupper($authStatus['dmarc'] ?? 'none')) ?>
                </span>
            </div>
        </div>
        <?php endif; ?>

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
                    <?php
                    // Display typosquatting warning if detected for this header
                    if (isset($headerTyposquattingFindings[$headerKey])):
                        $finding = $headerTyposquattingFindings[$headerKey];
                    ?>
                        <div class="typosquat-alert">
                            <span class="alert-icon">⚠️</span>
                            <span class="alert-text">
                                Typosquatting detected: domain resembles <strong><?= $e($finding['matched_safe_domain']) ?></strong>
                                <?php if (!empty($finding['details'])): ?>
                                    <br><small class="alert-details"><?= $e($finding['details']) ?></small>
                                <?php endif; ?>
                            </span>
                        </div>
                    <?php endif; ?>
                    <?php
                    // Display malicious domain warning if detected for this header
                    if (isset($headerMaliciousFindings[$headerKey])):
                        $mFinding = $headerMaliciousFindings[$headerKey];
                    ?>
                        <div class="typosquat-alert" style="background: rgba(220, 53, 69, 0.1); border-color: var(--color-error, #dc3545);">
                            <span class="alert-icon">&#9888;</span>
                            <span class="alert-text" style="color: var(--color-error, #dc3545);">
                                <strong>Malicious domain:</strong> matches known threat <strong><?= $e($mFinding['matched_malicious_domain'] ?? '') ?></strong>
                            </span>
                        </div>
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
                        <?php if (($currentUser['role'] ?? 'user') === 'admin'): ?>
                        <th>Actions</th>
                        <?php endif; ?>
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
                            <div class="vt-cell-container">
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
                            </div>
                        </td>
                        <?php if (($currentUser['role'] ?? 'user') === 'admin'): ?>
                        <td class="actions-cell">
                            <button class="btn btn-sm btn-add-safe"
                                    data-url="<?= $e($link['url']) ?>"
                                    data-domain="<?= $e($link['domain'] ?? parse_url($link['url'], PHP_URL_HOST) ?? '') ?>"
                                    onclick="addDomainToSafeList(this)">
                                + Safe
                            </button>
                            <button class="btn btn-sm btn-danger"
                                    data-url="<?= $e($link['url']) ?>"
                                    data-domain="<?= $e($link['domain'] ?? parse_url($link['url'], PHP_URL_HOST) ?? '') ?>"
                                    onclick="addDomainToMaliciousList(this)"
                                    style="margin-left: 4px;">
                                + Malicious
                            </button>
                        </td>
                        <?php endif; ?>
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
                                <ul class="links-list paginated-list" data-paginate="20">
                                    <?php foreach ($details['links'] as $link): ?>
                                        <li class="link-item risk-<?= $e($link['risk_level'] ?? 'low') ?>">
                                            <span class="link-url"><?= $e($link['url']) ?></span>
                                            <span class="link-score">Score: <?= (int)$link['score'] ?></span>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                                <div class="pagination-controls"></div>
                            </div>
                        <?php endif;

                        // Attachments display
                        if (!empty($details['attachments'])): ?>
                            <div class="detail-item">
                                <strong>Attachments:</strong>
                                <ul class="attachments-list paginated-list" data-paginate="20">
                                    <?php foreach ($details['attachments'] as $att): ?>
                                        <li class="attachment-item risk-<?= $e($att['risk_level']) ?>">
                                            <span class="att-name"><?= $e($att['filename']) ?></span>
                                            <span class="att-type"><?= $e($att['content_type']) ?></span>
                                            <span class="att-risk"><?= ucfirst($e($att['risk_level'])) ?> risk</span>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                                <div class="pagination-controls"></div>
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

                        // VirusTotal URL results
                        if (!empty($details['results'])): ?>
                            <div class="detail-item">
                                <strong>VirusTotal Scans (<?= count($details['results']) ?>):</strong>
                                <ul class="vt-results-list" data-paginate="20">
                                    <?php foreach ($details['results'] as $vtEntry): ?>
                                        <?php
                                            $malicious = $vtEntry['result']['stats']['malicious'] ?? 0;
                                            $suspicious = $vtEntry['result']['stats']['suspicious'] ?? 0;
                                            $detectionRate = $vtEntry['result']['detection_rate'] ?? '0/0';
                                            $scannedAt = $vtEntry['scanned_at'] ?? '';

                                            $statusClass = 'success';
                                            $statusText = 'Clean';
                                            if ($malicious > 0) {
                                                $statusClass = 'error';
                                                $statusText = 'Malicious';
                                            } elseif ($suspicious > 0) {
                                                $statusClass = 'warning';
                                                $statusText = 'Suspicious';
                                            }
                                        ?>
                                        <li class="vt-result-item">
                                            <div class="vt-result-url"><?= $e($vtEntry['url']) ?></div>
                                            <div class="vt-result-info">
                                                <span class="badge badge-<?= $statusClass ?>"><?= $e($detectionRate) ?></span>
                                                <span class="vt-result-status"><?= $e($statusText) ?></span>
                                                <?php if ($scannedAt): ?>
                                                    <span class="vt-result-time">(<?= $e($scannedAt) ?>)</span>
                                                <?php endif; ?>
                                            </div>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                                <div class="pagination-controls" data-target="vt-results-list"></div>
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
