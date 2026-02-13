<?php
use Ephishchk\Security\OutputEncoder;
$e = fn($v) => OutputEncoder::html($v ?? '');
?>
<?php ob_start(); ?>

<div class="admin-page">
    <h1>Malicious Domains Management</h1>
    <p class="subtitle">Manage known malicious domains for confirmed phish detection</p>

    <!-- Information Card -->
    <div class="card info-card" style="border-left: 4px solid var(--color-error, #dc3545);">
        <h3>How Malicious Domain Detection Works</h3>
        <p>Domains added to this list are treated as <strong>known threats</strong>. When a scanned email contains any match against this list, the scan is automatically flagged as a <strong>confirmed phish</strong> with a maximum risk score of 100.</p>

        <div class="detection-methods">
            <div class="method">
                <strong>Header Matching:</strong>
                <p>From, Reply-To, and Return-Path domains are checked against this list.</p>
                <code>evil-phish.com in From header = Confirmed Phish</code>
            </div>
            <div class="method">
                <strong>Link Matching:</strong>
                <p>Every URL domain found in the email body is checked against this list.</p>
                <code>https://evil-phish.com/login = Confirmed Phish</code>
            </div>
            <div class="method">
                <strong>Subdomain Matching:</strong>
                <p>Subdomains of malicious domains are also matched automatically.</p>
                <code>login.evil-phish.com also matches evil-phish.com</code>
            </div>
        </div>
    </div>

    <!-- Add Domain Form -->
    <div class="card">
        <h2>Add New Malicious Domain</h2>
        <form method="POST" action="/admin/malicious-domains/add" class="safe-domain-form">
            <?= $csrfField ?>
            <div class="form-group">
                <label for="domain">Domain</label>
                <input type="text"
                       id="domain"
                       name="domain"
                       placeholder="evil-phish.com"
                       required>
                <small class="form-help">Enter domain name only (e.g., "evil-phish.com", not "https://evil-phish.com")</small>
            </div>
            <div class="form-group">
                <label for="notes">Notes (Optional)</label>
                <input type="text"
                       id="notes"
                       name="notes"
                       placeholder="e.g., Known phishing domain, Credential harvester">
            </div>
            <button type="submit" class="btn btn-primary">Add Domain</button>
        </form>
    </div>

    <!-- Import/Export -->
    <div class="card">
        <h2>Import & Export</h2>
        <p class="card-description">Bulk import domains from CSV or export your current list</p>

        <div class="import-export-grid">
            <!-- Export -->
            <div class="export-section">
                <h3>Export Domains</h3>
                <p>Download all malicious domains as a CSV file</p>
                <a href="/admin/malicious-domains/export" class="btn btn-secondary">
                    Export CSV
                </a>
            </div>

            <!-- Import -->
            <div class="import-section">
                <h3>Import Domains</h3>
                <p>Upload a CSV file to add domains in bulk</p>
                <form method="POST" action="/admin/malicious-domains/import" enctype="multipart/form-data" class="import-form">
                    <?= $csrfField ?>
                    <div class="file-input-wrapper">
                        <input type="file"
                               id="csv_file"
                               name="csv_file"
                               accept=".csv"
                               required>
                        <label for="csv_file" class="file-label">
                            <span class="file-text">Choose CSV file...</span>
                        </label>
                    </div>
                    <button type="submit" class="btn btn-primary">Upload & Import</button>
                </form>
                <small class="form-help">
                    <strong>CSV format:</strong> domain, notes<br>
                    Example: evil-phish.com, Known phishing domain<br>
                    Duplicates are automatically skipped<br>
                    Invalid domains are skipped
                </small>
            </div>
        </div>
    </div>

    <!-- Malicious Domains List -->
    <div class="card">
        <div class="card-header-with-search">
            <h2>Malicious Domains List (<span id="domain-count"><?= $total ?></span> total)</h2>
            <?php if (!empty($domains)): ?>
            <div class="search-box">
                <input type="text"
                       id="domain-search"
                       placeholder="Search current page..."
                       class="search-input">
            </div>
            <?php endif; ?>
        </div>

        <?php if (empty($domains)): ?>
        <p class="no-data">No malicious domains configured yet.</p>
        <?php else: ?>
        <p id="no-results" class="no-data" style="display: none;">No domains match your search.</p>
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
                        <td><?= $e($domain['added_by_username'] ?? 'System') ?></td>
                        <td><?= $e(date('M j, Y', strtotime($domain['created_at']))) ?></td>
                        <td><?= $e($domain['notes'] ?? '-') ?></td>
                        <td class="actions">
                            <form method="POST"
                                  action="/admin/malicious-domains/delete"
                                  class="inline-form"
                                  onsubmit="return confirm('Are you sure you want to remove <?= $e($domain['domain']) ?> from the malicious domains list?');">
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

        <?php if ($totalPages > 1): ?>
        <div class="pagination">
            <?php
            $currentPage = $page ?? 1;
            $queryParams = $_GET;
            unset($queryParams['page']);
            $baseUrl = '/admin/malicious-domains?' . http_build_query($queryParams);
            $baseUrl = rtrim($baseUrl, '?');
            $separator = empty($queryParams) ? '?' : '&';
            ?>

            <!-- First Page -->
            <?php if ($currentPage > 1): ?>
                <a href="<?= $baseUrl . $separator ?>page=1" class="pagination-btn" title="First Page">&laquo;</a>
            <?php else: ?>
                <span class="pagination-btn disabled" title="First Page">&laquo;</span>
            <?php endif; ?>

            <!-- Previous Page -->
            <?php if ($currentPage > 1): ?>
                <a href="<?= $baseUrl . $separator ?>page=<?= $currentPage - 1 ?>" class="pagination-btn" title="Previous Page">&lsaquo;</a>
            <?php else: ?>
                <span class="pagination-btn disabled" title="Previous Page">&lsaquo;</span>
            <?php endif; ?>

            <!-- Page Numbers -->
            <?php
            $startPage = max(1, $currentPage - 2);
            $endPage = min($totalPages, $currentPage + 2);

            if ($currentPage <= 3) {
                $endPage = min(5, $totalPages);
            }
            if ($currentPage >= $totalPages - 2) {
                $startPage = max(1, $totalPages - 4);
            }

            for ($i = $startPage; $i <= $endPage; $i++):
            ?>
                <?php if ($i == $currentPage): ?>
                    <span class="pagination-btn active"><?= $i ?></span>
                <?php else: ?>
                    <a href="<?= $baseUrl . $separator ?>page=<?= $i ?>" class="pagination-btn"><?= $i ?></a>
                <?php endif; ?>
            <?php endfor; ?>

            <!-- Next Page -->
            <?php if ($currentPage < $totalPages): ?>
                <a href="<?= $baseUrl . $separator ?>page=<?= $currentPage + 1 ?>" class="pagination-btn" title="Next Page">&rsaquo;</a>
            <?php else: ?>
                <span class="pagination-btn disabled" title="Next Page">&rsaquo;</span>
            <?php endif; ?>

            <!-- Last Page -->
            <?php if ($currentPage < $totalPages): ?>
                <a href="<?= $baseUrl . $separator ?>page=<?= $totalPages ?>" class="pagination-btn" title="Last Page">&raquo;</a>
            <?php else: ?>
                <span class="pagination-btn disabled" title="Last Page">&raquo;</span>
            <?php endif; ?>

            <span class="pagination-info">
                Showing <?= count($domains) ?> of <?= $total ?> domains
            </span>
        </div>
        <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Quick Guide -->
    <div class="card help-card">
        <h3>Adding Domains from Scan Results</h3>
        <p>When viewing scan results, admins can quickly add domains to the malicious list:</p>
        <ol>
            <li>Navigate to any scan result with URLs</li>
            <li>Click the <strong>"+ Malicious"</strong> button next to any URL</li>
            <li>The domain will be automatically added to this list</li>
            <li>Future scans containing this domain will be flagged as confirmed phish</li>
        </ol>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const domainInput = document.getElementById('domain');
    if (domainInput) {
        domainInput.focus();

        domainInput.addEventListener('blur', function() {
            let value = this.value.trim();
            value = value.replace(/^https?:\/\//i, '');
            value = value.replace(/^www\./i, '');
            value = value.replace(/\/$/, '');
            value = value.replace(/\/.*$/, '');
            this.value = value.toLowerCase();
        });
    }

    const fileInput = document.getElementById('csv_file');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            const fileLabel = this.nextElementSibling;
            const fileText = fileLabel.querySelector('.file-text');
            if (this.files && this.files.length > 0) {
                fileText.textContent = this.files[0].name;
            } else {
                fileText.textContent = 'Choose CSV file...';
            }
        });
    }

    const searchInput = document.getElementById('domain-search');
    if (searchInput) {
        const table = document.querySelector('.safe-domains-table tbody');
        const rows = table ? table.querySelectorAll('tr') : [];
        const noResultsMessage = document.getElementById('no-results');

        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase().trim();
            let visibleCount = 0;

            rows.forEach(row => {
                const domain = row.querySelector('.domain-code')?.textContent.toLowerCase() || '';
                const notes = row.querySelector('td:nth-child(4)')?.textContent.toLowerCase() || '';
                const addedBy = row.querySelector('td:nth-child(2)')?.textContent.toLowerCase() || '';

                const matches = domain.includes(searchTerm) ||
                               notes.includes(searchTerm) ||
                               addedBy.includes(searchTerm);

                if (matches) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });

            if (visibleCount === 0 && searchTerm !== '') {
                noResultsMessage.style.display = 'block';
                table.parentElement.style.display = 'none';
            } else {
                noResultsMessage.style.display = 'none';
                table.parentElement.style.display = '';
            }
        });

        searchInput.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                this.value = '';
                this.dispatchEvent(new Event('input'));
            }
        });
    }
});
</script>

<?php $content = ob_get_clean(); ?>
<?php include __DIR__ . '/../layout.php'; ?>
