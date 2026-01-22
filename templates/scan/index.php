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
            <p>Check email authentication (SPF, DKIM, DMARC) for an email address.</p>

            <form method="POST" action="/scan/quick" class="scan-form">
                <?= $csrfField ?>
                <div class="form-group">
                    <label for="quick-input">Email Address</label>
                    <input type="text" id="quick-input" name="input"
                           placeholder="example@domain.com"
                           value="<?= $e($input ?? '') ?>" required>
                </div>
                <button type="submit" class="btn btn-primary">Check Authentication</button>
            </form>
        </div>
    </div>

    <div class="tab-content <?= $activeTab === 'full' ? 'active' : '' ?>" id="tab-full">
        <div class="card">
            <h2>Full Email Analysis</h2>
            <p>Upload an .eml file or paste the complete raw email source (including headers) for comprehensive analysis.</p>

            <form method="POST" action="/scan/full" class="scan-form" enctype="multipart/form-data">
                <?= $csrfField ?>

                <div class="input-method-toggle">
                    <label class="toggle-option">
                        <input type="radio" name="input_method" value="paste" checked onchange="toggleInputMethod(this.value)">
                        <span>Paste Email Content</span>
                    </label>
                    <label class="toggle-option">
                        <input type="radio" name="input_method" value="upload" onchange="toggleInputMethod(this.value)">
                        <span>Upload .eml File</span>
                    </label>
                </div>

                <div class="form-group" id="paste-input">
                    <label for="email-content">Raw Email Content</label>
                    <textarea id="email-content" name="email_content" rows="15"
                              placeholder="Paste the raw email source here...&#10;&#10;To get raw email:&#10;- Gmail: Open email → Menu (⋮) → Show original&#10;- Outlook: Open email → File → Properties → Internet headers"></textarea>
                </div>

                <div class="form-group" id="upload-input" style="display: none;">
                    <label for="eml-file">Upload .eml File</label>
                    <div class="file-upload-area" id="drop-zone">
                        <input type="file" id="eml-file" name="eml_file" accept=".eml,.msg,message/rfc822">
                        <div class="file-upload-text">
                            <span class="upload-icon">📧</span>
                            <p>Drag & drop your .eml file here or click to browse</p>
                            <p class="file-hint">Supports .eml files up to 10MB</p>
                        </div>
                        <div class="file-selected" id="file-selected" style="display: none;">
                            <span class="file-icon">📄</span>
                            <span class="file-name" id="file-name"></span>
                            <button type="button" class="file-remove" onclick="clearFile()">×</button>
                        </div>
                    </div>
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
