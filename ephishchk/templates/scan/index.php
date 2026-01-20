<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v);
$activeTab = $activeTab ?? 'quick';
?>
<?php ob_start(); ?>

<div class="scan-page">
    <h1>Email Phishing Checker</h1>
    <p class="subtitle">Analyze emails and domains for phishing indicators</p>

    <div class="tabs">
        <button class="tab <?= $activeTab === 'quick' ? 'active' : '' ?>" data-tab="quick">Quick Check</button>
        <button class="tab <?= $activeTab === 'full' ? 'active' : '' ?>" data-tab="full">Full Analysis</button>
    </div>

    <div class="tab-content <?= $activeTab === 'quick' ? 'active' : '' ?>" id="tab-quick">
        <div class="card">
            <h2>Quick Check</h2>
            <p>Check email authentication (SPF, DKIM, DMARC) for a domain or email address.</p>

            <form method="POST" action="/scan/quick" class="scan-form">
                <?= $csrfField ?>
                <div class="form-group">
                    <label for="quick-input">Email Address or Domain</label>
                    <input type="text" id="quick-input" name="input"
                           placeholder="example@domain.com or domain.com"
                           value="<?= $e($input ?? '') ?>" required>
                </div>
                <button type="submit" class="btn btn-primary">Check Authentication</button>
            </form>
        </div>
    </div>

    <div class="tab-content <?= $activeTab === 'full' ? 'active' : '' ?>" id="tab-full">
        <div class="card">
            <h2>Full Email Analysis</h2>
            <p>Paste the complete raw email source (including headers) for comprehensive analysis.</p>

            <form method="POST" action="/scan/full" class="scan-form">
                <?= $csrfField ?>
                <div class="form-group">
                    <label for="email-content">Raw Email Content</label>
                    <textarea id="email-content" name="email_content" rows="15"
                              placeholder="Paste the raw email source here...&#10;&#10;To get raw email:&#10;- Gmail: Open email → Menu (⋮) → Show original&#10;- Outlook: Open email → File → Properties → Internet headers"
                              required></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Analyze Email</button>
            </form>
        </div>
    </div>

    <div class="info-cards">
        <div class="info-card">
            <h3>What We Check</h3>
            <ul>
                <li><strong>SPF</strong> - Sender Policy Framework</li>
                <li><strong>DKIM</strong> - DomainKeys Identified Mail</li>
                <li><strong>DMARC</strong> - Domain-based Message Authentication</li>
                <li><strong>Headers</strong> - Suspicious patterns</li>
                <li><strong>Links</strong> - URL reputation analysis</li>
                <li><strong>Attachments</strong> - File type risk assessment</li>
            </ul>
        </div>
        <div class="info-card">
            <h3>Privacy</h3>
            <p>Your email content is processed locally and not stored permanently. Only scan metadata is retained for history purposes.</p>
        </div>
    </div>
</div>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
