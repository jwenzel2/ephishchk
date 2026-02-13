<?php

declare(strict_types=1);

namespace Ephishchk\Services\VirusTotal;

/**
 * VirusTotal API Client
 */
class VirusTotalClient
{
    private const API_BASE = 'https://www.virustotal.com/api/v3';

    private ?string $apiKey;
    private RateLimiter $rateLimiter;
    private int $timeout;

    public function __construct(?string $apiKey, RateLimiter $rateLimiter, int $timeout = 30)
    {
        $this->apiKey = $apiKey;
        $this->rateLimiter = $rateLimiter;
        $this->timeout = $timeout;
    }

    /**
     * Check if client is configured (has API key)
     */
    public function isConfigured(): bool
    {
        return !empty($this->apiKey);
    }

    /**
     * Test API connection
     */
    public function testConnection(): array
    {
        if (!$this->isConfigured()) {
            return [
                'success' => false,
                'error' => 'API key not configured',
            ];
        }

        try {
            // Make a simple request to check API key
            $response = $this->request('GET', '/users/current');

            return [
                'success' => true,
                'user' => $response['data']['id'] ?? 'Unknown',
                'quota' => $response['data']['attributes']['quotas'] ?? [],
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Get file report by hash (SHA-256, SHA-1, or MD5)
     */
    public function getFileReport(string $hash): array
    {
        if (!$this->isConfigured()) {
            return ['error' => 'API key not configured'];
        }

        if (!$this->rateLimiter->canMakeRequest()) {
            return [
                'error' => 'Rate limit exceeded',
                'rate_limit' => $this->rateLimiter->getStatus(),
            ];
        }

        try {
            $this->rateLimiter->recordRequest();
            $response = $this->request('GET', "/files/$hash");

            return $this->parseFileReport($response);
        } catch (VirusTotalException $e) {
            if ($e->getCode() === 404) {
                return ['error' => 'File not found in VirusTotal database'];
            }
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * Upload file for scanning
     */
    public function uploadFile(string $filePath): array
    {
        if (!$this->isConfigured()) {
            return ['error' => 'API key not configured'];
        }

        if (!file_exists($filePath)) {
            return ['error' => 'File not found'];
        }

        $fileSize = filesize($filePath);

        // Check file size (32MB limit for standard upload)
        if ($fileSize > 33554432) {
            return ['error' => 'File too large (max 32MB)'];
        }

        if (!$this->rateLimiter->canMakeRequest()) {
            return [
                'error' => 'Rate limit exceeded',
                'rate_limit' => $this->rateLimiter->getStatus(),
            ];
        }

        try {
            $this->rateLimiter->recordRequest();

            $boundary = uniqid('', true);
            $filename = basename($filePath);
            $content = file_get_contents($filePath);

            $body = "--$boundary\r\n";
            $body .= "Content-Disposition: form-data; name=\"file\"; filename=\"$filename\"\r\n";
            $body .= "Content-Type: application/octet-stream\r\n\r\n";
            $body .= $content . "\r\n";
            $body .= "--$boundary--\r\n";

            $response = $this->request('POST', '/files', $body, [
                'Content-Type: multipart/form-data; boundary=' . $boundary,
            ]);

            return [
                'success' => true,
                'analysis_id' => $response['data']['id'] ?? null,
                'message' => 'File submitted for analysis',
            ];
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * Get URL report
     */
    public function getUrlReport(string $url): array
    {
        if (!$this->isConfigured()) {
            return ['error' => 'API key not configured'];
        }

        if (!$this->rateLimiter->canMakeRequest()) {
            return [
                'error' => 'Rate limit exceeded',
                'rate_limit' => $this->rateLimiter->getStatus(),
            ];
        }

        try {
            // URL ID is base64 encoded URL without padding
            $urlId = rtrim(base64_encode($url), '=');

            $this->rateLimiter->recordRequest();
            $response = $this->request('GET', "/urls/$urlId");

            return $this->parseUrlReport($response);
        } catch (VirusTotalException $e) {
            if ($e->getCode() === 404) {
                return ['error' => 'URL not found in VirusTotal database'];
            }
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * Submit URL for scanning
     */
    public function scanUrl(string $url): array
    {
        if (!$this->isConfigured()) {
            return ['error' => 'API key not configured'];
        }

        if (!$this->rateLimiter->canMakeRequest()) {
            return [
                'error' => 'Rate limit exceeded',
                'rate_limit' => $this->rateLimiter->getStatus(),
            ];
        }

        try {
            $this->rateLimiter->recordRequest();
            $response = $this->request('POST', '/urls', http_build_query(['url' => $url]), [
                'Content-Type: application/x-www-form-urlencoded',
            ]);

            return [
                'success' => true,
                'analysis_id' => $response['data']['id'] ?? null,
                'message' => 'URL submitted for analysis',
            ];
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * Get analysis status
     */
    public function getAnalysis(string $analysisId): array
    {
        if (!$this->isConfigured()) {
            return ['error' => 'API key not configured'];
        }

        if (!$this->rateLimiter->canMakeRequest()) {
            return [
                'error' => 'Rate limit exceeded',
                'rate_limit' => $this->rateLimiter->getStatus(),
            ];
        }

        try {
            $this->rateLimiter->recordRequest();
            $response = $this->request('GET', "/analyses/$analysisId");

            $status = $response['data']['attributes']['status'] ?? 'unknown';

            $result = [
                'status' => $status,
                'analysis_id' => $analysisId,
            ];

            if ($status === 'completed') {
                $stats = $response['data']['attributes']['stats'] ?? [];
                $result['stats'] = $stats;
                $result['malicious'] = $stats['malicious'] ?? 0;
                $result['suspicious'] = $stats['suspicious'] ?? 0;
                $result['undetected'] = $stats['undetected'] ?? 0;
                $result['total'] = array_sum($stats);
            }

            return $result;
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * Parse file report response
     */
    private function parseFileReport(array $response): array
    {
        $attributes = $response['data']['attributes'] ?? [];
        $stats = $attributes['last_analysis_stats'] ?? [];

        return [
            'found' => true,
            'sha256' => $attributes['sha256'] ?? null,
            'sha1' => $attributes['sha1'] ?? null,
            'md5' => $attributes['md5'] ?? null,
            'size' => $attributes['size'] ?? null,
            'type' => $attributes['type_description'] ?? $attributes['magic'] ?? null,
            'names' => $attributes['names'] ?? [],
            'stats' => [
                'malicious' => $stats['malicious'] ?? 0,
                'suspicious' => $stats['suspicious'] ?? 0,
                'undetected' => $stats['undetected'] ?? 0,
                'harmless' => $stats['harmless'] ?? 0,
                'timeout' => $stats['timeout'] ?? 0,
                'failure' => $stats['failure'] ?? 0,
            ],
            'total_vendors' => array_sum($stats),
            'detection_rate' => $this->calculateDetectionRate($stats),
            'last_analysis_date' => isset($attributes['last_analysis_date'])
                ? date('Y-m-d H:i:s', $attributes['last_analysis_date'])
                : null,
            'reputation' => $attributes['reputation'] ?? 0,
            'tags' => $attributes['tags'] ?? [],
        ];
    }

    /**
     * Parse URL report response
     */
    private function parseUrlReport(array $response): array
    {
        $attributes = $response['data']['attributes'] ?? [];
        $stats = $attributes['last_analysis_stats'] ?? [];

        return [
            'found' => true,
            'url' => $attributes['url'] ?? null,
            'final_url' => $attributes['last_final_url'] ?? null,
            'stats' => [
                'malicious' => $stats['malicious'] ?? 0,
                'suspicious' => $stats['suspicious'] ?? 0,
                'undetected' => $stats['undetected'] ?? 0,
                'harmless' => $stats['harmless'] ?? 0,
                'timeout' => $stats['timeout'] ?? 0,
            ],
            'total_vendors' => array_sum($stats),
            'detection_rate' => $this->calculateDetectionRate($stats),
            'last_analysis_date' => isset($attributes['last_analysis_date'])
                ? date('Y-m-d H:i:s', $attributes['last_analysis_date'])
                : null,
            'categories' => $attributes['categories'] ?? [],
            'reputation' => $attributes['reputation'] ?? 0,
            'tags' => $attributes['tags'] ?? [],
        ];
    }

    /**
     * Calculate detection rate string
     */
    private function calculateDetectionRate(array $stats): string
    {
        $malicious = ($stats['malicious'] ?? 0) + ($stats['suspicious'] ?? 0);
        $total = array_sum($stats);

        if ($total === 0) {
            return '0/0';
        }

        return "$malicious/$total";
    }

    /**
     * Make HTTP request to VirusTotal API
     */
    private function request(string $method, string $endpoint, ?string $body = null, array $extraHeaders = []): array
    {
        $url = self::API_BASE . $endpoint;

        $headers = array_merge([
            'x-apikey: ' . $this->apiKey,
            'Accept: application/json',
        ], $extraHeaders);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new VirusTotalException("cURL error: $error");
        }

        $data = json_decode($response, true);

        if ($httpCode === 404) {
            throw new VirusTotalException('Resource not found', 404);
        }

        if ($httpCode === 401) {
            throw new VirusTotalException('Invalid API key', 401);
        }

        if ($httpCode === 429) {
            throw new VirusTotalException('Rate limit exceeded', 429);
        }

        if ($httpCode >= 400) {
            $message = $data['error']['message'] ?? 'API error';
            throw new VirusTotalException($message, $httpCode);
        }

        return $data ?? [];
    }

    /**
     * Get rate limiter status
     */
    public function getRateLimitStatus(): array
    {
        return $this->rateLimiter->getStatus();
    }
}

/**
 * VirusTotal Exception
 */
class VirusTotalException extends \Exception
{
}
