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
