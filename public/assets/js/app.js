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
    // Remove any existing inline notification
    const existingNotif = element.parentElement.querySelector('.inline-notification');
    if (existingNotif) {
        existingNotif.remove();
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.className = `inline-notification inline-notification-${type}`;
    notification.textContent = message;

    // Insert after the element
    element.parentElement.appendChild(notification);

    // Auto-remove after duration (if duration > 0)
    if (duration > 0) {
        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        }, duration);
    }

    return notification;
}

/**
 * Scan individual URL with VirusTotal
 */
async function scanUrlWithVirusTotal(button) {
    const scanId = button.dataset.scanId;
    const url = button.dataset.url;

    if (!scanId || !url) {
        showInlineNotification(button, 'Invalid scan parameters', 'error');
        return;
    }

    // Remove any existing notification
    const existingNotif = button.parentElement.querySelector('.inline-notification');
    if (existingNotif) {
        existingNotif.remove();
    }

    // Update button to loading state
    button.disabled = true;
    button.textContent = 'Scanning...';
    button.classList.add('loading');

    try {
        const response = await fetch(`/scan/${scanId}/url/virustotal`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: new URLSearchParams({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            // Handle rate limit error
            if (response.status === 429) {
                const retryAfter = data.retry_after || 60;
                button.disabled = false;
                button.textContent = 'Scan with VT';
                button.classList.remove('loading');

                showInlineNotification(
                    button,
                    `Rate limit exceeded. Please wait ${retryAfter} seconds before scanning.`,
                    'warning',
                    0  // Don't auto-dismiss
                );
                return;
            }

            // Handle VT not configured error
            if (response.status === 503) {
                button.disabled = false;
                button.textContent = 'Scan with VT';
                button.classList.remove('loading');

                showInlineNotification(button, 'VirusTotal is not configured', 'error');
                return;
            }

            // Generic error
            throw new Error(data.error || 'Failed to scan URL');
        }

        // Success - update UI
        const result = data.result;
        const malicious = result.stats?.malicious || 0;
        const suspicious = result.stats?.suspicious || 0;
        const detectionRate = result.detection_rate || '0/0';

        let status = 'Clean';
        let badgeClass = 'success';
        if (malicious > 0) {
            status = 'Malicious';
            badgeClass = 'error';
        } else if (suspicious > 0) {
            status = 'Suspicious';
            badgeClass = 'warning';
        }

        // Replace button with result badge
        const resultHtml = `
            <div class="vt-result">
                <span class="badge badge-${badgeClass}">${escapeHtml(detectionRate)}</span>
                <span class="vt-status">${escapeHtml(status)}</span>
            </div>
        `;
        const parentCell = button.parentElement;
        parentCell.innerHTML = resultHtml;

        // Show success notification under the result
        const vtResult = parentCell.querySelector('.vt-result');
        showInlineNotification(vtResult, 'Scan successful!', 'success', 3000);

        // Update overall risk score
        updateRiskScore(data.risk_score);

    } catch (error) {
        showInlineNotification(button, error.message, 'error');

        // Re-enable button
        button.disabled = false;
        button.textContent = 'Scan with VT';
        button.classList.remove('loading');
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
