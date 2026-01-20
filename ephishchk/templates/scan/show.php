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
                        <?php endif; ?>

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
