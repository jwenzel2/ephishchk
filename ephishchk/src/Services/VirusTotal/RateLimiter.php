<?php

declare(strict_types=1);

namespace Ephishchk\Services\VirusTotal;

use Ephishchk\Core\Database;

/**
 * Rate Limiter for VirusTotal API
 */
class RateLimiter
{
    private Database $db;
    private string $apiName;
    private int $perMinute;
    private int $perDay;

    public function __construct(Database $db, string $apiName = 'virustotal', int $perMinute = 4, int $perDay = 500)
    {
        $this->db = $db;
        $this->apiName = $apiName;
        $this->perMinute = $perMinute;
        $this->perDay = $perDay;
    }

    /**
     * Set rate limits (for switching between free/premium)
     */
    public function setLimits(int $perMinute, int $perDay): void
    {
        $this->perMinute = $perMinute;
        $this->perDay = $perDay;
    }

    /**
     * Check if we can make a request
     */
    public function canMakeRequest(): bool
    {
        $this->cleanupOldWindows();

        // Check minute limit
        $minuteCount = $this->getCount('minute');
        if ($minuteCount >= $this->perMinute) {
            return false;
        }

        // Check daily limit
        $dayCount = $this->getCount('day');
        if ($dayCount >= $this->perDay) {
            return false;
        }

        return true;
    }

    /**
     * Record a request
     */
    public function recordRequest(): void
    {
        $this->cleanupOldWindows();

        // Update minute counter
        $this->incrementCount('minute');

        // Update day counter
        $this->incrementCount('day');
    }

    /**
     * Get current count for a window type
     */
    public function getCount(string $windowType): int
    {
        $row = $this->db->fetchOne(
            'SELECT request_count, window_start FROM rate_limits WHERE api_name = ? AND window_type = ?',
            [$this->apiName, $windowType]
        );

        if (!$row) {
            return 0;
        }

        // Check if window has expired
        $windowStart = strtotime($row['window_start']);
        $windowDuration = $windowType === 'minute' ? 60 : 86400;

        if (time() - $windowStart >= $windowDuration) {
            return 0;
        }

        return (int) $row['request_count'];
    }

    /**
     * Get remaining requests for a window type
     */
    public function getRemaining(string $windowType): int
    {
        $limit = $windowType === 'minute' ? $this->perMinute : $this->perDay;
        return max(0, $limit - $this->getCount($windowType));
    }

    /**
     * Get time until window resets (in seconds)
     */
    public function getResetTime(string $windowType): int
    {
        $row = $this->db->fetchOne(
            'SELECT window_start FROM rate_limits WHERE api_name = ? AND window_type = ?',
            [$this->apiName, $windowType]
        );

        if (!$row) {
            return 0;
        }

        $windowStart = strtotime($row['window_start']);
        $windowDuration = $windowType === 'minute' ? 60 : 86400;
        $resetTime = $windowStart + $windowDuration;

        return max(0, $resetTime - time());
    }

    /**
     * Get rate limit status
     */
    public function getStatus(): array
    {
        return [
            'minute' => [
                'used' => $this->getCount('minute'),
                'limit' => $this->perMinute,
                'remaining' => $this->getRemaining('minute'),
                'resets_in' => $this->getResetTime('minute'),
            ],
            'day' => [
                'used' => $this->getCount('day'),
                'limit' => $this->perDay,
                'remaining' => $this->getRemaining('day'),
                'resets_in' => $this->getResetTime('day'),
            ],
        ];
    }

    /**
     * Wait until we can make a request (blocking)
     */
    public function waitForAvailability(int $maxWaitSeconds = 60): bool
    {
        $waited = 0;

        while (!$this->canMakeRequest() && $waited < $maxWaitSeconds) {
            $waitTime = min(5, $this->getResetTime('minute'));
            if ($waitTime <= 0) {
                $waitTime = 1;
            }

            sleep($waitTime);
            $waited += $waitTime;
        }

        return $this->canMakeRequest();
    }

    /**
     * Increment count for a window type
     */
    private function incrementCount(string $windowType): void
    {
        $windowDuration = $windowType === 'minute' ? 60 : 86400;

        // Try to update existing row
        $result = $this->db->query(
            'UPDATE rate_limits SET request_count = request_count + 1
             WHERE api_name = ? AND window_type = ?
             AND window_start >= DATE_SUB(NOW(), INTERVAL ? SECOND)',
            [$this->apiName, $windowType, $windowDuration]
        );

        if ($result->rowCount() === 0) {
            // Need to reset the window
            $this->db->query(
                'INSERT INTO rate_limits (api_name, window_type, request_count, window_start)
                 VALUES (?, ?, 1, NOW())
                 ON DUPLICATE KEY UPDATE request_count = 1, window_start = NOW()',
                [$this->apiName, $windowType]
            );
        }
    }

    /**
     * Clean up expired windows
     */
    private function cleanupOldWindows(): void
    {
        // Reset minute window if expired
        $this->db->query(
            'UPDATE rate_limits SET request_count = 0, window_start = NOW()
             WHERE api_name = ? AND window_type = ?
             AND window_start < DATE_SUB(NOW(), INTERVAL 60 SECOND)',
            [$this->apiName, 'minute']
        );

        // Reset day window if expired
        $this->db->query(
            'UPDATE rate_limits SET request_count = 0, window_start = NOW()
             WHERE api_name = ? AND window_type = ?
             AND window_start < DATE_SUB(NOW(), INTERVAL 1 DAY)',
            [$this->apiName, 'day']
        );
    }

    /**
     * Reset all counters (for testing)
     */
    public function reset(): void
    {
        $this->db->query(
            'UPDATE rate_limits SET request_count = 0, window_start = NOW() WHERE api_name = ?',
            [$this->apiName]
        );
    }
}
