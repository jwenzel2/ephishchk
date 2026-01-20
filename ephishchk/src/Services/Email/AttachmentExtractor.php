<?php

declare(strict_types=1);

namespace Ephishchk\Services\Email;

/**
 * Attachment Extractor Service
 */
class AttachmentExtractor
{
    private string $tempPath;
    private int $maxSize;

    // Potentially dangerous file extensions
    private const DANGEROUS_EXTENSIONS = [
        'exe', 'bat', 'cmd', 'com', 'msi', 'scr', 'pif',
        'vbs', 'vbe', 'js', 'jse', 'ws', 'wsf', 'wsc', 'wsh',
        'ps1', 'ps1xml', 'ps2', 'ps2xml', 'psc1', 'psc2',
        'dll', 'cpl', 'msc', 'jar',
        'hta', 'htm', 'html', // Can contain scripts
        'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pptm', // Can contain macros
        'pdf', // Can contain scripts
        'iso', 'img', // Disk images
        'zip', 'rar', '7z', 'tar', 'gz', // Archives that might contain malware
        'lnk', 'url', // Shortcuts
    ];

    // Known safe extensions
    private const SAFE_EXTENSIONS = [
        'txt', 'csv', 'log',
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg',
        'mp3', 'mp4', 'avi', 'mov', 'wav',
    ];

    public function __construct(string $tempPath, int $maxSize = 33554432)
    {
        $this->tempPath = rtrim($tempPath, '/\\');
        $this->maxSize = $maxSize;

        if (!is_dir($this->tempPath)) {
            mkdir($this->tempPath, 0755, true);
        }
    }

    /**
     * Extract attachments from a parsed email
     *
     * @return array<int, array{filename: string, content_type: string, size: int, extension: string, risk_level: string, hash_sha256: string, temp_path: ?string}>
     */
    public function extract(ParsedEmail $email): array
    {
        $attachments = $email->getAttachments();
        $extracted = [];

        foreach ($attachments as $i => $attachment) {
            $filename = $attachment['filename'] ?? 'attachment_' . $i;
            $content = $attachment['content'] ?? '';
            $contentType = $attachment['content_type'] ?? 'application/octet-stream';
            $size = strlen($content);

            // Get file extension
            $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

            // Calculate hash
            $hash = hash('sha256', $content);

            // Assess risk level
            $riskLevel = $this->assessRiskLevel($extension, $contentType);

            $extractedAttachment = [
                'filename' => $this->sanitizeFilename($filename),
                'original_filename' => $filename,
                'content_type' => $contentType,
                'size' => $size,
                'extension' => $extension,
                'risk_level' => $riskLevel,
                'hash_sha256' => $hash,
                'temp_path' => null,
            ];

            // Save to temp file if within size limit (for VirusTotal scanning)
            if ($size <= $this->maxSize && $size > 0) {
                $tempFile = $this->saveTempFile($content, $hash, $extension);
                if ($tempFile) {
                    $extractedAttachment['temp_path'] = $tempFile;
                }
            } elseif ($size > $this->maxSize) {
                $extractedAttachment['warning'] = 'File too large for scanning';
            }

            $extracted[] = $extractedAttachment;
        }

        return $extracted;
    }

    /**
     * Assess risk level of an attachment
     */
    private function assessRiskLevel(string $extension, string $contentType): string
    {
        // Check for double extensions (e.g., document.pdf.exe)
        if (in_array($extension, self::DANGEROUS_EXTENSIONS)) {
            return 'high';
        }

        if (in_array($extension, self::SAFE_EXTENSIONS)) {
            return 'low';
        }

        // Check content type
        $dangerousTypes = [
            'application/x-msdownload',
            'application/x-executable',
            'application/x-dosexec',
            'application/x-msdos-program',
            'application/x-sh',
            'application/x-shellscript',
            'application/javascript',
            'text/javascript',
        ];

        if (in_array(strtolower($contentType), $dangerousTypes)) {
            return 'high';
        }

        // Office documents with macros
        if (str_ends_with($extension, 'm') && in_array(substr($extension, 0, -1) . 'x', ['docx', 'xlsx', 'pptx'])) {
            return 'high';
        }

        return 'medium';
    }

    /**
     * Sanitize filename to prevent path traversal
     */
    private function sanitizeFilename(string $filename): string
    {
        // Remove path components
        $filename = basename($filename);

        // Remove null bytes
        $filename = str_replace("\0", '', $filename);

        // Remove potentially dangerous characters
        $filename = preg_replace('/[<>:"\/\\|?*\x00-\x1f]/', '_', $filename);

        // Limit length
        if (strlen($filename) > 255) {
            $ext = pathinfo($filename, PATHINFO_EXTENSION);
            $name = substr(pathinfo($filename, PATHINFO_FILENAME), 0, 250 - strlen($ext));
            $filename = $name . '.' . $ext;
        }

        return $filename;
    }

    /**
     * Save attachment to temporary file
     */
    private function saveTempFile(string $content, string $hash, string $extension): ?string
    {
        $filename = $hash . ($extension ? '.' . $extension : '');
        $path = $this->tempPath . DIRECTORY_SEPARATOR . $filename;

        if (file_put_contents($path, $content) !== false) {
            return $path;
        }

        return null;
    }

    /**
     * Clean up temporary files older than specified age
     */
    public function cleanup(int $maxAgeSeconds = 3600): int
    {
        $deleted = 0;
        $now = time();

        $files = glob($this->tempPath . '/*');
        foreach ($files as $file) {
            if (is_file($file) && ($now - filemtime($file)) > $maxAgeSeconds) {
                if (unlink($file)) {
                    $deleted++;
                }
            }
        }

        return $deleted;
    }

    /**
     * Delete a specific temporary file
     */
    public function deleteTempFile(string $path): bool
    {
        // Ensure the path is within our temp directory
        $realPath = realpath($path);
        $realTempPath = realpath($this->tempPath);

        if ($realPath && $realTempPath && str_starts_with($realPath, $realTempPath)) {
            return unlink($realPath);
        }

        return false;
    }

    /**
     * Get list of dangerous extensions
     */
    public function getDangerousExtensions(): array
    {
        return self::DANGEROUS_EXTENSIONS;
    }

    /**
     * Check if extension is dangerous
     */
    public function isExtensionDangerous(string $extension): bool
    {
        return in_array(strtolower($extension), self::DANGEROUS_EXTENSIONS);
    }

    /**
     * Get human-readable file size
     */
    public static function formatFileSize(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;

        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }

        return round($bytes, 2) . ' ' . $units[$i];
    }
}
