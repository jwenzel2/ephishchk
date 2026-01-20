<?php

declare(strict_types=1);

namespace Ephishchk\Services;

use Ephishchk\Core\Application;
use Ephishchk\Core\Logger;
use Ephishchk\Models\Scan;
use Ephishchk\Models\ScanResult;
use Ephishchk\Models\Setting;
use Ephishchk\Services\Authentication\DnsLookupService;
use Ephishchk\Services\Authentication\SpfCheckerService;
use Ephishchk\Services\Authentication\DkimCheckerService;
use Ephishchk\Services\Authentication\DmarcCheckerService;
use Ephishchk\Services\Email\EmailParserService;
use Ephishchk\Services\Email\HeaderAnalyzerService;
use Ephishchk\Services\Email\AttachmentExtractor;
use Ephishchk\Services\Scanner\LinkExtractorService;
use Ephishchk\Services\Scanner\LinkAnalyzerService;
use Ephishchk\Services\VirusTotal\RateLimiter;
use Ephishchk\Services\VirusTotal\VirusTotalClient;
use Ephishchk\Security\InputSanitizer;

/**
 * Scan Orchestrator - coordinates all scanning services
 */
class ScanOrchestrator
{
    private Application $app;
    private Logger $logger;
    private Scan $scanModel;
    private ScanResult $resultModel;
    private Setting $settingModel;

    // Services
    private DnsLookupService $dns;
    private SpfCheckerService $spf;
    private DkimCheckerService $dkim;
    private DmarcCheckerService $dmarc;
    private EmailParserService $emailParser;
    private HeaderAnalyzerService $headerAnalyzer;
    private AttachmentExtractor $attachmentExtractor;
    private LinkExtractorService $linkExtractor;
    private LinkAnalyzerService $linkAnalyzer;
    private ?VirusTotalClient $virusTotal = null;

    public function __construct(Application $app)
    {
        $this->app = $app;
        $this->logger = Logger::getInstance();

        $this->logger->info('ScanOrchestrator initializing');

        try {
            $db = $app->getDatabase();
            $config = $app->getConfig();

            $this->logger->debug('Database connection obtained');

            // Initialize models
            $this->scanModel = new Scan($db);
            $this->resultModel = new ScanResult($db);
            $this->settingModel = new Setting($db, $config['encryption_key'] ?? '');

            $this->logger->debug('Models initialized');

            // Initialize services
            $this->dns = new DnsLookupService($config['dns_cache_ttl'] ?? 300);
            $this->spf = new SpfCheckerService($this->dns);
            $this->dkim = new DkimCheckerService($this->dns, $config['dkim_selectors'] ?? []);
            $this->dmarc = new DmarcCheckerService($this->dns);
            $this->emailParser = new EmailParserService();
            $this->headerAnalyzer = new HeaderAnalyzerService($config);
            $this->attachmentExtractor = new AttachmentExtractor(
                $config['paths']['temp'] ?? sys_get_temp_dir(),
                $config['max_attachment_size'] ?? 33554432
            );
            $this->linkExtractor = new LinkExtractorService($config['max_links_per_scan'] ?? 50);
            $this->linkAnalyzer = new LinkAnalyzerService($this->dns);

            $this->logger->debug('Services initialized');

            // Initialize VirusTotal client if configured
            $this->initializeVirusTotal($db);

            $this->logger->info('ScanOrchestrator initialized successfully');

        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Failed to initialize ScanOrchestrator');
            throw $e;
        }
    }

    private function initializeVirusTotal($db): void
    {
        try {
            $apiKey = $this->settingModel->get('virustotal_api_key');
            if ($apiKey) {
                $tier = $this->settingModel->get('virustotal_tier', 'free');
                $limits = $this->app->getConfig('rate_limits.virustotal.' . $tier);

                $rateLimiter = new RateLimiter(
                    $db,
                    'virustotal',
                    $limits['per_minute'] ?? 4,
                    $limits['per_day'] ?? 500
                );

                $this->virusTotal = new VirusTotalClient($apiKey, $rateLimiter);
                $this->logger->info('VirusTotal client initialized', ['tier' => $tier]);
            } else {
                $this->logger->debug('VirusTotal not configured (no API key)');
            }
        } catch (\Throwable $e) {
            $this->logger->warning('Failed to initialize VirusTotal', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Perform quick check (domain/email authentication only)
     */
    public function quickCheck(string $input, string $ipAddress): array
    {
        $this->logger->info('Quick check started', ['input' => $input, 'ip' => $ipAddress]);

        // Determine if input is email or domain
        $domain = $this->extractDomain($input);
        if (!$domain) {
            $this->logger->warning('Invalid input for quick check', ['input' => $input]);
            return ['error' => 'Invalid email address or domain'];
        }

        $this->logger->debug('Domain extracted', ['domain' => $domain]);

        try {
            // Create scan record
            $scanId = $this->scanModel->create([
                'scan_type' => 'quick',
                'input_identifier' => $input,
                'ip_address' => $ipAddress,
            ]);

            $this->logger->info('Scan record created', ['scan_id' => $scanId]);

            $this->scanModel->updateStatus($scanId, 'processing');

            // Run authentication checks
            $this->runAuthenticationChecks($scanId, $domain);

            // Calculate overall risk score
            $riskScore = $this->calculateRiskScore($scanId);
            $this->scanModel->updateStatus($scanId, 'completed', $riskScore);

            $this->logger->info('Quick check completed', ['scan_id' => $scanId, 'risk_score' => $riskScore]);

            return $this->scanModel->findWithResults($scanId);

        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Quick check failed', ['input' => $input]);

            if (isset($scanId)) {
                $this->scanModel->updateStatus($scanId, 'failed');
                $this->resultModel->create([
                    'scan_id' => $scanId,
                    'check_type' => 'error',
                    'status' => 'error',
                    'summary' => 'Scan failed: ' . $e->getMessage(),
                ]);
                return $this->scanModel->findWithResults($scanId);
            }

            return ['error' => 'Scan failed: ' . $e->getMessage()];
        }
    }

    /**
     * Perform full email analysis
     */
    public function fullAnalysis(string $rawEmail, string $ipAddress): array
    {
        $this->logger->info('Full analysis started', ['ip' => $ipAddress, 'email_size' => strlen($rawEmail)]);

        // Size check
        $maxSize = $this->app->getConfig('max_email_size') ?? 10485760;
        if (strlen($rawEmail) > $maxSize) {
            $this->logger->warning('Email too large', ['size' => strlen($rawEmail), 'max' => $maxSize]);
            return ['error' => 'Email content too large'];
        }

        // Parse email
        $this->logger->debug('Parsing email');
        $email = $this->emailParser->parse($rawEmail);
        if (!$email) {
            $this->logger->warning('Failed to parse email');
            return ['error' => 'Failed to parse email content'];
        }

        $from = $email->getFrom();
        $identifier = $from['email'] ?? $email->getSubject() ?? 'Unknown sender';
        $this->logger->debug('Email parsed', ['from' => $identifier]);

        try {
            // Create scan record
            $scanId = $this->scanModel->create([
                'scan_type' => 'full',
                'input_identifier' => $identifier,
                'ip_address' => $ipAddress,
            ]);

            $this->logger->info('Scan record created', ['scan_id' => $scanId]);

            $this->scanModel->updateStatus($scanId, 'processing');

            // Get sender domain
            $domain = $email->getSenderDomain();
            $this->logger->debug('Sender domain', ['domain' => $domain]);

            // Run authentication checks if we have a domain
            if ($domain) {
                $this->runAuthenticationChecks($scanId, $domain);
            }

            // Analyze headers
            $this->logger->debug('Analyzing headers');
            $this->runHeaderAnalysis($scanId, $email);

            // Extract and analyze links
            $this->logger->debug('Analyzing links');
            $this->runLinkAnalysis($scanId, $email);

            // Extract and scan attachments
            $this->logger->debug('Analyzing attachments');
            $this->runAttachmentAnalysis($scanId, $email);

            // Calculate overall risk score
            $riskScore = $this->calculateRiskScore($scanId);
            $this->scanModel->updateStatus($scanId, 'completed', $riskScore);

            $this->logger->info('Full analysis completed', ['scan_id' => $scanId, 'risk_score' => $riskScore]);

            return $this->scanModel->findWithResults($scanId);

        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Full analysis failed');

            if (isset($scanId)) {
                $this->scanModel->updateStatus($scanId, 'failed');
                $this->resultModel->create([
                    'scan_id' => $scanId,
                    'check_type' => 'error',
                    'status' => 'error',
                    'summary' => 'Scan failed: ' . $e->getMessage(),
                ]);
                return $this->scanModel->findWithResults($scanId);
            }

            return ['error' => 'Scan failed: ' . $e->getMessage()];
        }
    }

    /**
     * Run SPF, DKIM, DMARC checks
     */
    private function runAuthenticationChecks(int $scanId, string $domain): void
    {
        $this->logger->debug('Running authentication checks', ['scan_id' => $scanId, 'domain' => $domain]);

        try {
            // SPF Check
            $this->logger->debug('Checking SPF');
            $spfResult = $this->spf->check($domain);
            $this->resultModel->create([
                'scan_id' => $scanId,
                'check_type' => 'spf',
                'status' => $spfResult['status'],
                'score' => $this->statusToScore($spfResult['status']),
                'summary' => $spfResult['record']
                    ? 'SPF record found'
                    : 'No SPF record',
                'details' => $spfResult,
            ]);
            $this->logger->debug('SPF check complete', ['status' => $spfResult['status']]);

            // DKIM Check
            $this->logger->debug('Checking DKIM');
            $dkimResult = $this->dkim->check($domain);
            $selectorCount = count($dkimResult['selectors'] ?? []);
            $this->resultModel->create([
                'scan_id' => $scanId,
                'check_type' => 'dkim',
                'status' => $dkimResult['status'],
                'score' => $this->statusToScore($dkimResult['status']),
                'summary' => $selectorCount > 0
                    ? "Found $selectorCount DKIM selector(s)"
                    : 'No DKIM records found for common selectors',
                'details' => $dkimResult,
            ]);
            $this->logger->debug('DKIM check complete', ['status' => $dkimResult['status'], 'selectors' => $selectorCount]);

            // DMARC Check
            $this->logger->debug('Checking DMARC');
            $dmarcResult = $this->dmarc->check($domain);
            $this->resultModel->create([
                'scan_id' => $scanId,
                'check_type' => 'dmarc',
                'status' => $dmarcResult['status'],
                'score' => $this->statusToScore($dmarcResult['status']),
                'summary' => $dmarcResult['record']
                    ? 'DMARC record found: ' . ($dmarcResult['details']['parsed']['policy'] ?? 'unknown') . ' policy'
                    : 'No DMARC record',
                'details' => $dmarcResult,
            ]);
            $this->logger->debug('DMARC check complete', ['status' => $dmarcResult['status']]);

        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Authentication checks failed', ['scan_id' => $scanId, 'domain' => $domain]);
            throw $e;
        }
    }

    /**
     * Run header analysis
     */
    private function runHeaderAnalysis(int $scanId, $email): void
    {
        try {
            $result = $this->headerAnalyzer->analyze($email);

            $status = 'pass';
            if ($result['score'] >= 50) {
                $status = 'fail';
            } elseif ($result['score'] >= 25) {
                $status = 'warning';
            }

            $this->resultModel->create([
                'scan_id' => $scanId,
                'check_type' => 'header',
                'status' => $status,
                'score' => 100 - $result['score'],
                'summary' => $result['summary'],
                'details' => $result,
            ]);

            $this->logger->debug('Header analysis complete', ['status' => $status, 'score' => $result['score']]);

        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Header analysis failed', ['scan_id' => $scanId]);
            throw $e;
        }
    }

    /**
     * Run link analysis
     */
    private function runLinkAnalysis(int $scanId, $email): void
    {
        try {
            $links = $this->linkExtractor->extractFromEmail($email);

            if (empty($links)) {
                $this->resultModel->create([
                    'scan_id' => $scanId,
                    'check_type' => 'links',
                    'status' => 'info',
                    'score' => 100,
                    'summary' => 'No links found in email',
                    'details' => ['links' => []],
                ]);
                $this->logger->debug('No links found in email');
                return;
            }

            $this->logger->debug('Links found', ['count' => count($links)]);

            $analyzed = $this->linkAnalyzer->analyzeMultiple($links);

            // Find highest risk
            $maxScore = 0;
            $suspiciousCount = 0;
            foreach ($analyzed as $link) {
                if ($link['score'] > $maxScore) {
                    $maxScore = $link['score'];
                }
                if ($link['score'] >= 25) {
                    $suspiciousCount++;
                }
            }

            $status = 'pass';
            if ($maxScore >= 50) {
                $status = 'fail';
            } elseif ($maxScore >= 25) {
                $status = 'warning';
            }

            $this->resultModel->create([
                'scan_id' => $scanId,
                'check_type' => 'links',
                'status' => $status,
                'score' => 100 - $maxScore,
                'summary' => count($links) . ' link(s) found, ' . $suspiciousCount . ' suspicious',
                'details' => [
                    'total_links' => count($links),
                    'suspicious_count' => $suspiciousCount,
                    'links' => $analyzed,
                ],
            ]);

            $this->logger->debug('Link analysis complete', ['total' => count($links), 'suspicious' => $suspiciousCount]);

            // Scan URLs with VirusTotal if enabled
            if ($this->virusTotal && $this->settingModel->get('enable_vt_url_scan', true)) {
                $this->scanLinksWithVirusTotal($scanId, $analyzed);
            }

        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Link analysis failed', ['scan_id' => $scanId]);
            throw $e;
        }
    }

    /**
     * Run attachment analysis
     */
    private function runAttachmentAnalysis(int $scanId, $email): void
    {
        try {
            if (!$email->hasAttachments()) {
                $this->resultModel->create([
                    'scan_id' => $scanId,
                    'check_type' => 'attachments',
                    'status' => 'info',
                    'score' => 100,
                    'summary' => 'No attachments found',
                    'details' => ['attachments' => []],
                ]);
                $this->logger->debug('No attachments found');
                return;
            }

            $attachments = $this->attachmentExtractor->extract($email);
            $this->logger->debug('Attachments found', ['count' => count($attachments)]);

            // Count by risk level
            $highRisk = 0;
            $mediumRisk = 0;
            foreach ($attachments as $att) {
                if ($att['risk_level'] === 'high') {
                    $highRisk++;
                } elseif ($att['risk_level'] === 'medium') {
                    $mediumRisk++;
                }
            }

            $status = 'pass';
            $score = 100;
            if ($highRisk > 0) {
                $status = 'fail';
                $score = max(0, 100 - ($highRisk * 30) - ($mediumRisk * 10));
            } elseif ($mediumRisk > 0) {
                $status = 'warning';
                $score = max(0, 100 - ($mediumRisk * 15));
            }

            // Remove actual content from details (too large)
            $attachmentDetails = array_map(function ($att) {
                unset($att['content']);
                return $att;
            }, $attachments);

            $this->resultModel->create([
                'scan_id' => $scanId,
                'check_type' => 'attachments',
                'status' => $status,
                'score' => $score,
                'summary' => count($attachments) . ' attachment(s) found, ' . $highRisk . ' high risk',
                'details' => [
                    'total_attachments' => count($attachments),
                    'high_risk_count' => $highRisk,
                    'medium_risk_count' => $mediumRisk,
                    'attachments' => $attachmentDetails,
                ],
            ]);

            $this->logger->debug('Attachment analysis complete', ['total' => count($attachments), 'high_risk' => $highRisk]);

            // Scan with VirusTotal if enabled
            if ($this->virusTotal && $this->settingModel->get('enable_vt_file_scan', true)) {
                $this->scanAttachmentsWithVirusTotal($scanId, $attachments);
            }

            // Clean up temp files
            foreach ($attachments as $att) {
                if (!empty($att['temp_path'])) {
                    $this->attachmentExtractor->deleteTempFile($att['temp_path']);
                }
            }

        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Attachment analysis failed', ['scan_id' => $scanId]);
            throw $e;
        }
    }

    /**
     * Scan links with VirusTotal
     */
    private function scanLinksWithVirusTotal(int $scanId, array $links): void
    {
        $vtResults = [];

        foreach ($links as $link) {
            // Skip if already low risk
            if ($link['score'] < 25) {
                continue;
            }

            $result = $this->virusTotal->getUrlReport($link['url']);
            if (!isset($result['error'])) {
                $vtResults[] = [
                    'url' => $link['url'],
                    'result' => $result,
                ];
            }

            // Respect rate limits
            if (!$this->virusTotal->getRateLimitStatus()['minute']['remaining']) {
                break;
            }
        }

        if (!empty($vtResults)) {
            $maliciousCount = 0;
            foreach ($vtResults as $vt) {
                if (($vt['result']['stats']['malicious'] ?? 0) > 0) {
                    $maliciousCount++;
                }
            }

            $status = $maliciousCount > 0 ? 'fail' : 'pass';

            $this->resultModel->create([
                'scan_id' => $scanId,
                'check_type' => 'virustotal_url',
                'status' => $status,
                'score' => $maliciousCount > 0 ? 0 : 100,
                'summary' => "Scanned " . count($vtResults) . " URL(s), $maliciousCount flagged",
                'details' => ['results' => $vtResults],
            ]);

            $this->logger->debug('VirusTotal URL scan complete', ['scanned' => count($vtResults), 'malicious' => $maliciousCount]);
        }
    }

    /**
     * Scan attachments with VirusTotal
     */
    private function scanAttachmentsWithVirusTotal(int $scanId, array $attachments): void
    {
        $vtResults = [];

        foreach ($attachments as $att) {
            if (empty($att['hash_sha256'])) {
                continue;
            }

            // Try hash lookup first
            $result = $this->virusTotal->getFileReport($att['hash_sha256']);

            if (isset($result['error']) && $result['error'] === 'File not found in VirusTotal database') {
                // File not known to VT - could upload if we have the temp file
                if (!empty($att['temp_path']) && file_exists($att['temp_path'])) {
                    $uploadResult = $this->virusTotal->uploadFile($att['temp_path']);
                    if (isset($uploadResult['analysis_id'])) {
                        $result = [
                            'uploaded' => true,
                            'analysis_id' => $uploadResult['analysis_id'],
                            'message' => 'File submitted for analysis',
                        ];
                    }
                }
            }

            if (!isset($result['error']) || isset($result['uploaded'])) {
                $vtResults[] = [
                    'filename' => $att['filename'],
                    'hash' => $att['hash_sha256'],
                    'result' => $result,
                ];
            }

            // Respect rate limits
            if (!$this->virusTotal->getRateLimitStatus()['minute']['remaining']) {
                break;
            }
        }

        if (!empty($vtResults)) {
            $maliciousCount = 0;
            foreach ($vtResults as $vt) {
                if (($vt['result']['stats']['malicious'] ?? 0) > 0) {
                    $maliciousCount++;
                }
            }

            $status = $maliciousCount > 0 ? 'fail' : 'pass';

            $this->resultModel->create([
                'scan_id' => $scanId,
                'check_type' => 'virustotal_file',
                'status' => $status,
                'score' => $maliciousCount > 0 ? 0 : 100,
                'summary' => "Scanned " . count($vtResults) . " file(s), $maliciousCount flagged",
                'details' => ['results' => $vtResults],
            ]);

            $this->logger->debug('VirusTotal file scan complete', ['scanned' => count($vtResults), 'malicious' => $maliciousCount]);
        }
    }

    /**
     * Calculate overall risk score for a scan
     */
    private function calculateRiskScore(int $scanId): int
    {
        $results = $this->resultModel->getByScanId($scanId);

        if (empty($results)) {
            return 50; // Unknown
        }

        $weights = [
            'spf' => 15,
            'dkim' => 15,
            'dmarc' => 20,
            'header' => 20,
            'links' => 15,
            'attachments' => 15,
            'virustotal_url' => 10,
            'virustotal_file' => 10,
        ];

        $totalWeight = 0;
        $weightedScore = 0;

        foreach ($results as $result) {
            $weight = $weights[$result['check_type']] ?? 5;
            $score = $result['score'] ?? 50;

            $totalWeight += $weight;
            $weightedScore += $score * $weight;
        }

        if ($totalWeight === 0) {
            return 50;
        }

        // Return as risk score (0 = low risk, 100 = high risk)
        // Invert because individual scores are 100 = good
        return 100 - (int) round($weightedScore / $totalWeight);
    }

    /**
     * Extract domain from email address or domain input
     */
    private function extractDomain(string $input): ?string
    {
        $input = InputSanitizer::string($input);

        // Check if it's an email address
        if (str_contains($input, '@')) {
            $email = InputSanitizer::validateEmail($input);
            if ($email) {
                $parts = explode('@', $email);
                return strtolower($parts[1]);
            }
            return null;
        }

        // Treat as domain
        return InputSanitizer::domain($input) ?: null;
    }

    /**
     * Convert status to score
     */
    private function statusToScore(string $status): int
    {
        return match ($status) {
            'pass' => 100,
            'warning' => 60,
            'fail' => 20,
            'info' => 80,
            default => 50,
        };
    }

    /**
     * Get scan model
     */
    public function getScanModel(): Scan
    {
        return $this->scanModel;
    }

    /**
     * Get result model
     */
    public function getResultModel(): ScanResult
    {
        return $this->resultModel;
    }

    /**
     * Get setting model
     */
    public function getSettingModel(): Setting
    {
        return $this->settingModel;
    }

    /**
     * Get VirusTotal client
     */
    public function getVirusTotalClient(): ?VirusTotalClient
    {
        return $this->virusTotal;
    }
}
