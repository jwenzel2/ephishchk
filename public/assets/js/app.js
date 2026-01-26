/**
 * ephishchk - Frontend JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    // Tab switching
    initTabs();

    // Form enhancements
    initForms();

    // File upload functionality
    initFileUpload();

    // Initialize pagination for all lists
    initPagination();

    // Apply auto theme if needed
    applyAutoTheme();

    // Auto-dismiss alerts after 20 seconds
    initAutoDismissAlerts();

    // Debug: Check CSRF token on page load
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta) {
        console.log('[Page Load] CSRF meta tag found');
        console.log('[Page Load] CSRF token:', csrfMeta.content?.substring(0, 16) + '... (length: ' + (csrfMeta.content?.length || 0) + ')');
    } else {
        console.error('[Page Load] CSRF meta tag NOT FOUND!');
    }
});

/**
 * Initialize tab switching functionality
 */
function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    const tabContents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const targetId = 'tab-' + this.dataset.tab;

            // Update active tab
            tabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');

            // Update active content
            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === targetId) {
                    content.classList.add('active');
                }
            });
        });
    });
}

/**
 * Initialize form enhancements
 */
function initForms() {
    // Add loading state to forms
    const forms = document.querySelectorAll('.scan-form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const btn = this.querySelector('button[type="submit"]');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Processing...';
            }
        });
    });

    // Auto-expand textarea for email content
    const emailTextarea = document.getElementById('email-content');
    if (emailTextarea) {
        emailTextarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 500) + 'px';
        });

        // Handle paste event for large content
        emailTextarea.addEventListener('paste', function(e) {
            // Allow the paste to complete then resize
            setTimeout(() => {
                this.style.height = 'auto';
                this.style.height = Math.min(this.scrollHeight, 500) + 'px';
            }, 0);
        });
    }
}

/**
 * Poll for scan status (used for async scans)
 */
function pollScanStatus(scanId, callback, interval = 2000) {
    const checkStatus = async () => {
        try {
            const response = await fetch(`/scan/${scanId}/status`, {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to fetch status');
            }

            const data = await response.json();
            callback(data);

            if (data.status === 'pending' || data.status === 'processing') {
                setTimeout(checkStatus, interval);
            }
        } catch (error) {
            console.error('Error polling status:', error);
            callback({ error: error.message });
        }
    };

    checkStatus();
}

/**
 * Format file size for display
 */
function formatFileSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;

    while (bytes >= 1024 && i < units.length - 1) {
        bytes /= 1024;
        i++;
    }

    return bytes.toFixed(2) + ' ' + units[i];
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        console.error('Failed to copy:', err);
        return false;
    }
}

/**
 * Show notification message
 */
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

/**
 * Toggle between paste and upload input methods
 */
function toggleInputMethod(method) {
    const pasteInput = document.getElementById('paste-input');
    const uploadInput = document.getElementById('upload-input');
    const emailContent = document.getElementById('email-content');
    const emlFile = document.getElementById('eml-file');

    if (method === 'upload') {
        pasteInput.style.display = 'none';
        uploadInput.style.display = 'block';
        if (emailContent) emailContent.removeAttribute('required');
    } else {
        pasteInput.style.display = 'block';
        uploadInput.style.display = 'none';
        if (emlFile) emlFile.value = '';
        clearFile();
    }
}

/**
 * Clear the selected file
 */
function clearFile() {
    const emlFile = document.getElementById('eml-file');
    const fileSelected = document.getElementById('file-selected');
    const uploadText = document.querySelector('.file-upload-text');

    if (emlFile) emlFile.value = '';
    if (fileSelected) fileSelected.style.display = 'none';
    if (uploadText) uploadText.style.display = 'block';
}

/**
 * Initialize file upload functionality
 */
function initFileUpload() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('eml-file');
    const fileSelected = document.getElementById('file-selected');
    const fileName = document.getElementById('file-name');
    const uploadText = document.querySelector('.file-upload-text');

    if (!dropZone || !fileInput) return;

    // Handle file selection
    fileInput.addEventListener('change', function() {
        handleFileSelect(this.files[0]);
    });

    // Drag and drop handling
    dropZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', function(e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.remove('drag-over');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            handleFileSelect(files[0]);
        }
    });

    function handleFileSelect(file) {
        if (!file) return;

        // Validate file extension
        const ext = file.name.split('.').pop().toLowerCase();
        if (!['eml', 'msg'].includes(ext)) {
            showNotification('Please select a valid .eml or .msg file', 'error');
            fileInput.value = '';
            return;
        }

        // Validate file size (10MB)
        if (file.size > 10 * 1024 * 1024) {
            showNotification('File size exceeds 10MB limit', 'error');
            fileInput.value = '';
            return;
        }

        // Show selected file
        if (fileName) fileName.textContent = file.name + ' (' + formatFileSize(file.size) + ')';
        if (fileSelected) fileSelected.style.display = 'flex';
        if (uploadText) uploadText.style.display = 'none';
    }
}

/**
 * Show inline notification below element
 */
function showInlineNotification(element, message, type = 'info', duration = 3000) {
    console.log('[Notification] Showing:', type, '-', message);

    // Find the container (vt-cell-container)
    const container = element.closest('.vt-cell-container');
    if (!container) {
        console.error('[Notification] Could not find vt-cell-container for element:', element);
        return null;
    }

    // Remove any existing inline notification
    const existingNotif = container.querySelector('.inline-notification');
    if (existingNotif) {
        console.log('[Notification] Removing existing notification');
        existingNotif.remove();
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.className = `inline-notification inline-notification-${type}`;
    notification.textContent = message;

    // Append to container
    container.appendChild(notification);
    console.log('[Notification] Notification added to container');

    // Auto-remove after duration (if duration > 0)
    if (duration > 0) {
        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => {
                notification.remove();
                console.log('[Notification] Notification auto-removed after', duration, 'ms');
            }, 300);
        }, duration);
    } else {
        console.log('[Notification] Notification will persist (duration = 0)');
    }

    return notification;
}

/**
 * Scan individual URL with VirusTotal
 */
async function scanUrlWithVirusTotal(button) {
    const scanId = button.dataset.scanId;
    const url = button.dataset.url;

    console.log('[VT Scan] Button clicked for URL:', url);

    if (!scanId || !url) {
        showInlineNotification(button, 'Invalid scan parameters', 'error');
        console.error('[VT Scan] Invalid parameters - scanId:', scanId, 'url:', url);
        return;
    }

    // Find container and remove any existing notification
    const container = button.closest('.vt-cell-container');
    if (!container) {
        console.error('[VT Scan] Could not find vt-cell-container');
        alert('Error: Could not find button container');
        return;
    }

    const existingNotif = container.querySelector('.inline-notification');
    if (existingNotif) {
        existingNotif.remove();
    }

    // Add initial "Submitting..." notification
    showInlineNotification(button, 'Submitting URL to VirusTotal...', 'info', 0);

    // Update button to loading state
    button.disabled = true;
    button.textContent = 'Scanning...';
    button.classList.add('loading');

    console.log('[VT Scan] Submitting request to /scan/' + scanId + '/url/virustotal');

    try {
        // Get CSRF token from meta tag
        const csrfTokenMeta = document.querySelector('meta[name="csrf-token"]');
        const csrfToken = csrfTokenMeta?.content || '';

        console.log('[VT Scan] Meta tag element:', csrfTokenMeta);
        console.log('[VT Scan] CSRF token value:', csrfToken);
        console.log('[VT Scan] CSRF token length:', csrfToken.length);

        if (!csrfToken) {
            console.error('[VT Scan] CSRF token not found in meta tag');
            alert('CSRF token not found. Please refresh the page.');
            throw new Error('CSRF token not found');
        }

        if (csrfToken.length !== 64) {
            console.warn('[VT Scan] CSRF token length is unexpected:', csrfToken.length, 'expected 64');
        }

        // Build request body explicitly
        const formData = new URLSearchParams();
        formData.append('url', url);
        formData.append('_csrf_token', csrfToken);

        const bodyString = formData.toString();
        console.log('[VT Scan] Request body string:', bodyString);
        console.log('[VT Scan] Body includes _csrf_token?', bodyString.includes('_csrf_token'));
        console.log('[VT Scan] Token in body:', bodyString.match(/_csrf_token=([^&]*)/)?.[1]?.substring(0, 16));

        const response = await fetch(`/scan/${scanId}/url/virustotal`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: formData
        });

        // Parse response
        let data;
        const contentType = response.headers.get('content-type');
        console.log('[VT Scan] Response content-type:', contentType);

        if (contentType && contentType.includes('application/json')) {
            data = await response.json();
        } else {
            // Non-JSON response (probably an error page)
            const responseText = await response.text();
            console.error('[VT Scan] Non-JSON response received:', responseText.substring(0, 500));
            throw new Error('Server returned invalid response. Please refresh the page and try again.');
        }

        // Handle "URL not found" (202 Accepted - submitted for scanning)
        if (response.status === 202 && data.not_found) {
            console.log('[VT Scan] URL not found, submitted for analysis');

            button.disabled = false;
            button.textContent = 'Scan with VT';
            button.classList.remove('loading');

            showInlineNotification(
                button,
                '📝 URL Not Previously Scanned\nSubmitted to VirusTotal for analysis.\nResults will be available later.',
                'info',
                10000  // Show for 10 seconds
            );
            return;
        }

        // Handle "URL not found" (404 - not found and couldn't submit)
        if (response.status === 404 && data.not_found) {
            console.log('[VT Scan] URL not found and could not submit');

            button.disabled = false;
            button.textContent = 'Scan with VT';
            button.classList.remove('loading');

            showInlineNotification(
                button,
                'ℹ️ URL Not in VirusTotal Database\nThis URL has not been scanned before.\nLikely a new or rarely-visited URL.',
                'info',
                10000
            );
            return;
        }

        if (!response.ok) {
            console.log('[VT Scan] Request failed with status:', response.status);
            console.log('[VT Scan] Error data:', data);

            // Handle CSRF token error
            if (response.status === 403 && data.error?.includes('CSRF')) {
                console.error('[VT Scan] CSRF token validation failed');
                console.error('[VT Scan] Debug info:', data.debug);

                button.disabled = false;
                button.textContent = 'Scan with VT';
                button.classList.remove('loading');

                let errorMsg = '❌ CSRF Token Error\nPlease refresh the page and try again.';
                if (data.debug) {
                    errorMsg += `\n\nDebug:\nSent: ${data.debug.submitted_length} chars (${data.debug.submitted_preview}...)\nExpected: ${data.debug.expected_length} chars (${data.debug.expected_preview}...)`;
                }

                showInlineNotification(
                    button,
                    errorMsg,
                    'error',
                    0
                );
                return;
            }

            // Handle rate limit error
            if (response.status === 429) {
                const retryAfter = data.retry_after || 60;
                console.log('[VT Scan] Rate limit exceeded. Retry after:', retryAfter);

                button.disabled = false;
                button.textContent = 'Scan with VT';
                button.classList.remove('loading');

                const message = `⚠️ Rate Limit Exceeded\nPlease wait ${retryAfter} seconds before scanning.\nVirusTotal free tier: 4 requests/minute`;
                showInlineNotification(
                    button,
                    message,
                    'warning',
                    0  // Don't auto-dismiss
                );
                return;
            }

            // Handle VT not configured error
            if (response.status === 503) {
                console.log('[VT Scan] VirusTotal not configured');

                button.disabled = false;
                button.textContent = 'Scan with VT';
                button.classList.remove('loading');

                showInlineNotification(button, '❌ VirusTotal is not configured', 'error');
                return;
            }

            // Generic error
            console.error('[VT Scan] Error:', data.error);
            throw new Error(data.error || 'Failed to scan URL');
        }

        // Success - update UI
        console.log('[VT Scan] Success! Response:', data);

        const result = data.result;
        const malicious = result.stats?.malicious || 0;
        const suspicious = result.stats?.suspicious || 0;
        const detectionRate = result.detection_rate || '0/0';

        let status = 'Clean';
        let badgeClass = 'success';
        let statusIcon = '✓';
        if (malicious > 0) {
            status = 'Malicious';
            badgeClass = 'error';
            statusIcon = '⚠️';
        } else if (suspicious > 0) {
            status = 'Suspicious';
            badgeClass = 'warning';
            statusIcon = '⚠';
        }

        console.log('[VT Scan] Detection:', detectionRate, '- Status:', status);

        // Replace button with result badge
        const resultHtml = `
            <div class="vt-result">
                <span class="badge badge-${badgeClass}">${escapeHtml(detectionRate)}</span>
                <span class="vt-status">${escapeHtml(status)}</span>
            </div>
        `;
        container.innerHTML = resultHtml;

        // Show success notification under the result
        const vtResult = container.querySelector('.vt-result');
        let successMsg = `${statusIcon} Scan Complete: ${status} (${detectionRate})`;

        // Add info about risk level change
        if (data.link_data) {
            const riskLevel = data.link_data.risk_level;
            if (riskLevel === 'low') {
                successMsg += '\n✓ URL Risk: Low (Clean)';
            } else if (riskLevel === 'high') {
                successMsg += '\n⚠️ URL Risk: High (Malicious)';
            } else if (riskLevel === 'medium') {
                successMsg += '\n⚠ URL Risk: Medium (Suspicious)';
            }
        }

        showInlineNotification(vtResult, successMsg, badgeClass === 'error' ? 'error' : 'success', 5000);

        // Update the URL row's risk badge if we have updated link data
        if (data.link_data) {
            updateUrlRiskBadge(url, data.link_data.risk_level);
        }

        // Update overall risk score
        updateRiskScore(data.risk_score);

        console.log('[VT Scan] Updated risk score to:', data.risk_score);

    } catch (error) {
        console.error('[VT Scan] Exception:', error);
        showInlineNotification(button, '❌ Error: ' + error.message, 'error', 0);

        // Re-enable button
        button.disabled = false;
        button.textContent = 'Scan with VT';
        button.classList.remove('loading');
    }
}

/**
 * Update URL row's risk badge based on new risk level
 */
function updateUrlRiskBadge(url, newRiskLevel) {
    console.log('[UI Update] Updating risk badge for URL:', url, 'to:', newRiskLevel);

    // Find all URL table rows
    const urlRows = document.querySelectorAll('.url-row');

    for (const row of urlRows) {
        const urlCell = row.querySelector('.url-text');
        if (urlCell && urlCell.textContent === url) {
            console.log('[UI Update] Found matching URL row');

            // Update row risk class
            row.className = row.className.replace(/risk-(low|medium|high)/, `risk-${newRiskLevel}`);

            // Update risk badge
            const riskCell = row.querySelector('.risk-cell');
            if (riskCell) {
                const badge = riskCell.querySelector('.badge');
                if (badge) {
                    // Remove old badge class
                    badge.className = badge.className.replace(/badge-(success|warning|error)/, '');

                    // Add new badge class
                    let badgeClass = 'success';
                    if (newRiskLevel === 'high') {
                        badgeClass = 'error';
                    } else if (newRiskLevel === 'medium') {
                        badgeClass = 'warning';
                    }

                    badge.classList.add(`badge-${badgeClass}`);
                    badge.textContent = newRiskLevel.charAt(0).toUpperCase() + newRiskLevel.slice(1);

                    console.log('[UI Update] Risk badge updated to:', newRiskLevel, 'with class:', badgeClass);
                }
            }

            break;
        }
    }
}

/**
 * Update risk score display
 */
function updateRiskScore(newScore) {
    const scoreElement = document.querySelector('.risk-score .score-value');
    const levelElement = document.querySelector('.risk-level');
    const riskScoreContainer = document.querySelector('.risk-score');

    if (!scoreElement) return;

    // Update score value
    scoreElement.textContent = newScore;

    // Determine risk level and class
    let riskLevel = 'Low';
    let riskClass = 'success';
    if (newScore >= 50) {
        riskLevel = 'High';
        riskClass = 'error';
    } else if (newScore >= 25) {
        riskLevel = 'Medium';
        riskClass = 'warning';
    }

    // Update risk level badge
    if (levelElement) {
        levelElement.textContent = `${riskLevel} Risk`;
        levelElement.className = `risk-level risk-${riskClass}`;
    }

    // Update risk score container class
    if (riskScoreContainer) {
        riskScoreContainer.className = `risk-score risk-${riskClass}`;
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Initialize pagination for all paginated lists
 */
function initPagination() {
    const paginatedLists = document.querySelectorAll('[data-paginate]');

    paginatedLists.forEach(list => {
        const itemsPerPage = parseInt(list.dataset.paginate) || 20;
        const items = Array.from(list.children);
        const totalItems = items.length;

        // Only paginate if we have more items than the limit
        if (totalItems <= itemsPerPage) {
            return;
        }

        // Find or create pagination controls
        let controlsContainer = list.nextElementSibling;
        if (!controlsContainer || !controlsContainer.classList.contains('pagination-controls')) {
            controlsContainer = document.createElement('div');
            controlsContainer.className = 'pagination-controls';
            list.parentNode.insertBefore(controlsContainer, list.nextSibling);
        }

        let currentPage = 1;
        const totalPages = Math.ceil(totalItems / itemsPerPage);

        const showPage = (page) => {
            const startIndex = (page - 1) * itemsPerPage;
            const endIndex = startIndex + itemsPerPage;

            items.forEach((item, index) => {
                if (index >= startIndex && index < endIndex) {
                    item.style.display = '';
                } else {
                    item.style.display = 'none';
                }
            });

            updatePaginationControls();
        };

        const updatePaginationControls = () => {
            controlsContainer.innerHTML = `
                <div class="pagination">
                    <button class="pagination-btn" ${currentPage === 1 ? 'disabled' : ''} onclick="changePage(this, -1)">
                        Previous
                    </button>
                    <span class="pagination-info">
                        Page ${currentPage} of ${totalPages} (${totalItems} items)
                    </span>
                    <button class="pagination-btn" ${currentPage === totalPages ? 'disabled' : ''} onclick="changePage(this, 1)">
                        Next
                    </button>
                </div>
            `;
        };

        // Store pagination data on the list element
        list._paginationData = {
            currentPage,
            totalPages,
            itemsPerPage,
            showPage: (page) => {
                currentPage = Math.max(1, Math.min(page, totalPages));
                showPage(currentPage);
            }
        };

        // Show first page
        showPage(1);
    });
}

/**
 * Change page for pagination
 */
function changePage(button, delta) {
    const controls = button.closest('.pagination-controls');
    const list = controls.previousElementSibling;

    if (list && list._paginationData) {
        const newPage = list._paginationData.currentPage + delta;
        list._paginationData.showPage(newPage);
    }
}

/**
 * Apply auto theme based on system preference
 */
function applyAutoTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');

    // Only apply if theme is set to "auto"
    if (currentTheme === 'auto') {
        // Check system preference
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

        if (prefersDark) {
            html.setAttribute('data-theme', 'dark');
        } else {
            html.setAttribute('data-theme', 'light');
        }

        // Listen for changes to system preference
        if (window.matchMedia) {
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
                // Only update if still in auto mode
                if (html.getAttribute('data-theme') === 'auto' || html.getAttribute('data-theme') === 'dark' || html.getAttribute('data-theme') === 'light') {
                    html.setAttribute('data-theme', e.matches ? 'dark' : 'light');
                }
            });
        }
    }
}

/**
 * Extract base domain from a domain with subdomains
 * Example: 'go.cloudplatformonline.com' -> 'cloudplatformonline.com'
 */
function extractBaseDomain(domain) {
    if (!domain) return domain;

    const parts = domain.toLowerCase().split('.');

    // If only 2 parts, return as-is
    if (parts.length <= 2) {
        return domain;
    }

    // Known two-part TLDs
    const twoPartTlds = ['co.uk', 'com.au', 'co.nz', 'co.za', 'com.br', 'co.jp'];
    const lastTwoParts = parts[parts.length - 2] + '.' + parts[parts.length - 1];

    if (twoPartTlds.includes(lastTwoParts)) {
        // Take last 3 parts for two-part TLDs
        if (parts.length >= 3) {
            return parts.slice(-3).join('.');
        }
    }

    // Default: take last 2 parts
    return parts.slice(-2).join('.');
}

/**
 * Add domain to safe list (admin only)
 */
async function addDomainToSafeList(button) {
    const fullDomain = button.dataset.domain;
    const url = button.dataset.url;

    console.log('[Safe Domain] Button clicked for domain:', fullDomain);

    if (!fullDomain) {
        showNotification('Invalid domain', 'error');
        console.error('[Safe Domain] Invalid domain - domain:', fullDomain);
        return;
    }

    // Extract base domain (remove subdomains)
    const baseDomain = extractBaseDomain(fullDomain);
    console.log('[Safe Domain] Extracted base domain:', baseDomain);

    // Confirm with user (show base domain that will be added)
    if (!confirm(`Add "${baseDomain}" to the safe domains list?\n\nThis domain will be used for typosquatting detection.`)) {
        console.log('[Safe Domain] User canceled');
        return;
    }

    // Use the base domain for submission
    const domain = baseDomain;

    // Update button to loading state
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Adding...';

    console.log('[Safe Domain] Submitting request to /admin/safe-domains/add-from-scan');

    try {
        // Get CSRF token from meta tag
        const csrfTokenMeta = document.querySelector('meta[name="csrf-token"]');
        const csrfToken = csrfTokenMeta?.content || '';

        if (!csrfToken) {
            console.error('[Safe Domain] CSRF token not found in meta tag');
            throw new Error('CSRF token not found. Please refresh the page.');
        }

        // Build request body
        const formData = new URLSearchParams();
        formData.append('domain', domain);
        formData.append('_csrf_token', csrfToken);

        const response = await fetch('/admin/safe-domains/add-from-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: formData
        });

        // Parse response
        let data;
        const contentType = response.headers.get('content-type');
        console.log('[Safe Domain] Response content-type:', contentType);

        if (contentType && contentType.includes('application/json')) {
            data = await response.json();
        } else {
            const responseText = await response.text();
            console.error('[Safe Domain] Non-JSON response received:', responseText.substring(0, 500));
            console.error('[Safe Domain] Full response status:', response.status, response.statusText);

            // Try to provide a more helpful error message
            if (response.status === 404) {
                throw new Error('Endpoint not found. Please refresh the page.');
            } else if (response.status === 500) {
                throw new Error('Server error occurred. Check console for details.');
            } else {
                throw new Error('Server returned invalid response. Please refresh the page and try again.');
            }
        }

        if (!response.ok) {
            console.log('[Safe Domain] Request failed with status:', response.status);
            console.log('[Safe Domain] Error data:', data);
            throw new Error(data.error || 'Failed to add domain to safe list');
        }

        // Success
        console.log('[Safe Domain] Success! Response:', data);

        // Update button to success state
        button.textContent = '✓ Safe';
        button.classList.add('btn-safe-added');
        button.disabled = true;

        // Show success notification
        showNotification(`Domain "${domain}" added to safe list successfully`, 'success');

    } catch (error) {
        console.error('[Safe Domain] Exception:', error);
        showNotification('Error: ' + error.message, 'error');

        // Restore button state
        button.disabled = false;
        button.textContent = originalText;
    }
}

/**
 * Initialize auto-dismiss functionality for alerts
 */
function initAutoDismissAlerts() {
    const alerts = document.querySelectorAll('.alert.auto-dismiss');

    alerts.forEach(alert => {
        // Add a close button
        const closeBtn = document.createElement('button');
        closeBtn.className = 'alert-close';
        closeBtn.innerHTML = '&times;';
        closeBtn.setAttribute('aria-label', 'Close');
        closeBtn.onclick = () => dismissAlert(alert);
        alert.appendChild(closeBtn);

        // Auto-dismiss after 20 seconds
        setTimeout(() => {
            dismissAlert(alert);
        }, 20000);
    });
}

/**
 * Dismiss an alert with fade-out animation
 */
function dismissAlert(alert) {
    alert.style.opacity = '0';
    alert.style.transition = 'opacity 0.5s ease';

    setTimeout(() => {
        alert.remove();
    }, 500);
}
