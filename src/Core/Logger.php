<?php

declare(strict_types=1);

namespace Ephishchk\Core;

/**
 * Simple file-based logger
 */
class Logger
{
    private static ?Logger $instance = null;
    private string $logPath;
    private string $logFile;
    private bool $debugMode;

    public const LEVEL_DEBUG = 'DEBUG';
    public const LEVEL_INFO = 'INFO';
    public const LEVEL_WARNING = 'WARNING';
    public const LEVEL_ERROR = 'ERROR';
    public const LEVEL_CRITICAL = 'CRITICAL';

    private function __construct(string $logPath, bool $debugMode = false)
    {
        $this->logPath = rtrim($logPath, '/\\');
        $this->debugMode = $debugMode;
        $this->logFile = $this->logPath . '/app_' . date('Y-m-d') . '.log';

        // Ensure log directory exists
        if (!is_dir($this->logPath)) {
            mkdir($this->logPath, 0755, true);
        }
    }

    public static function getInstance(?string $logPath = null, bool $debugMode = false): self
    {
        if (self::$instance === null) {
            $path = $logPath ?? (defined('BASE_PATH') ? BASE_PATH . '/storage/logs' : sys_get_temp_dir());
            self::$instance = new self($path, $debugMode);
        }
        return self::$instance;
    }

    public static function setInstance(Logger $logger): void
    {
        self::$instance = $logger;
    }

    /**
     * Log a debug message
     */
    public function debug(string $message, array $context = []): void
    {
        if ($this->debugMode) {
            $this->log(self::LEVEL_DEBUG, $message, $context);
        }
    }

    /**
     * Log an info message
     */
    public function info(string $message, array $context = []): void
    {
        $this->log(self::LEVEL_INFO, $message, $context);
    }

    /**
     * Log a warning message
     */
    public function warning(string $message, array $context = []): void
    {
        $this->log(self::LEVEL_WARNING, $message, $context);
    }

    /**
     * Log an error message
     */
    public function error(string $message, array $context = []): void
    {
        $this->log(self::LEVEL_ERROR, $message, $context);
    }

    /**
     * Log a critical message
     */
    public function critical(string $message, array $context = []): void
    {
        $this->log(self::LEVEL_CRITICAL, $message, $context);
    }

    /**
     * Log an exception
     */
    public function exception(\Throwable $e, string $message = '', array $context = []): void
    {
        $context['exception'] = [
            'class' => get_class($e),
            'message' => $e->getMessage(),
            'code' => $e->getCode(),
            'file' => $e->getFile(),
            'line' => $e->getLine(),
            'trace' => $e->getTraceAsString(),
        ];

        $logMessage = $message ?: 'Exception: ' . $e->getMessage();
        $this->log(self::LEVEL_ERROR, $logMessage, $context);
    }

    /**
     * Log a message with context
     */
    public function log(string $level, string $message, array $context = []): void
    {
        $timestamp = date('Y-m-d H:i:s');
        $contextStr = !empty($context) ? ' ' . json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : '';

        $logLine = sprintf(
            "[%s] [%s] %s%s\n",
            $timestamp,
            $level,
            $message,
            $contextStr
        );

        // Write to file
        file_put_contents($this->logFile, $logLine, FILE_APPEND | LOCK_EX);

        // Also write to PHP error log for critical errors
        if ($level === self::LEVEL_CRITICAL || $level === self::LEVEL_ERROR) {
            error_log("ephishchk [$level] $message");
        }
    }

    /**
     * Get the current log file path
     */
    public function getLogFile(): string
    {
        return $this->logFile;
    }

    /**
     * Get recent log entries
     */
    public function getRecentLogs(int $lines = 100): array
    {
        if (!file_exists($this->logFile)) {
            return [];
        }

        $file = new \SplFileObject($this->logFile, 'r');
        $file->seek(PHP_INT_MAX);
        $totalLines = $file->key();

        $startLine = max(0, $totalLines - $lines);
        $logs = [];

        $file->seek($startLine);
        while (!$file->eof()) {
            $line = $file->fgets();
            if (trim($line) !== '') {
                $logs[] = $line;
            }
        }

        return $logs;
    }

    /**
     * Get all log files
     */
    public function getLogFiles(): array
    {
        $files = glob($this->logPath . '/app_*.log');
        rsort($files); // Most recent first
        return $files;
    }

    /**
     * Clear old log files (older than X days)
     */
    public function clearOldLogs(int $daysToKeep = 30): int
    {
        $deleted = 0;
        $cutoff = time() - ($daysToKeep * 86400);

        foreach ($this->getLogFiles() as $file) {
            if (filemtime($file) < $cutoff) {
                if (unlink($file)) {
                    $deleted++;
                }
            }
        }

        return $deleted;
    }
}
