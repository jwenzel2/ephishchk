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
    public function quickCheck(string $input, string $ipAddress, ?int $userId = null): array
    {
        $this->logger->info('Quick check started', ['input' => $input, 'ip' => $ipAddress, 'user_id' => $userId]);

        // Determine if input is email or domain
        $domain = $this->extractDomain($input);
        if (!$domain) {
            $this->logger->warning('Invalid input for quick check', ['input' => $input]);
            return ['error' => 'Invalid email address'];
        }

        $this->logger->debug('Domain extracted', ['domain' => $domain]);

        try {
            // Create scan record
            $scanData = [
                'scan_type' => 'quick',
                'input_identifier' => $input,
                'ip_address' => $ipAddress,
            ];
            if ($userId !== null) {
                $scanData['user_id'] = $userId;
            }
            $scanId = $this->scanModel->create($scanData);

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
    public function fullAnalysis(string $rawEmail, string $ipAddress, ?int $userId = null): array
    {
        $this->logger->info('Full analysis started', ['ip' => $ipAddress, 'email_size' => strlen($rawEmail), 'user_id' => $userId]);

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
            $scanData = [
                'scan_type' => 'full',
                'input_identifier' => $identifier,
                'ip_address' => $ipAddress,
            ];
            if ($userId !== null) {
                $scanData['user_id'] = $userId;
            }
            $scanId = $this->scanModel->create($scanData);

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

            // Extract key headers for display
            $extractedHeaders = $this->extractKeyHeaders($email);
            $result['extracted_headers'] = $extractedHeaders;

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
     * Extract key email headers for display
     */
    private function extractKeyHeaders($email): array
    {
        $headers = [];

        // From
        $from = $email->getFrom();
        if ($from) {
            $headers['from'] = [
                'label' => 'From',
                'value' => $from['email'] ?? '',
                'display_name' => $from['name'] ?? '',
                'full' => $from['name'] ? "{$from['name']} <{$from['email']}>" : $from['email'],
            ];
        }

        // Reply-To
        $replyTo = $email->getReplyTo();
        if ($replyTo) {
            $headers['reply_to'] = [
                'label' => 'Reply-To',
                'value' => $replyTo['email'] ?? '',
                'display_name' => $replyTo['name'] ?? '',
                'full' => $replyTo['name'] ? "{$replyTo['name']} <{$replyTo['email']}>" : $replyTo['email'],
            ];
        }

        // Return-Path
        $returnPath = $email->getReturnPath();
        if ($returnPath) {
            $headers['return_path'] = [
                'label' => 'Return-Path',
                'value' => $returnPath,
                'full' => $returnPath,
            ];
        }

        // To
        $to = $email->getTo();
        if (!empty($to)) {
            $toAddresses = array_map(function ($addr) {
                return $addr['name'] ? "{$addr['name']} <{$addr['email']}>" : $addr['email'];
            }, $to);
            $headers['to'] = [
                'label' => 'To',
                'value' => implode(', ', array_column($to, 'email')),
                'addresses' => $to,
                'full' => implode(', ', $toAddresses),
            ];
        }

        // CC
        $cc = $email->getCc();
        if (!empty($cc)) {
            $ccAddresses = array_map(function ($addr) {
                return $addr['name'] ? "{$addr['name']} <{$addr['email']}>" : $addr['email'];
            }, $cc);
            $headers['cc'] = [
                'label' => 'CC',
                'value' => implode(', ', array_column($cc, 'email')),
                'addresses' => $cc,
                'full' => implode(', ', $ccAddresses),
            ];
        }

        // Subject
        $subject = $email->getSubject();
        if ($subject) {
            $headers['subject'] = [
                'label' => 'Subject',
                'value' => $subject,
                'full' => $subject,
            ];
        }

        // Date
        $date = $email->getDate();
        if ($date) {
            $headers['date'] = [
                'label' => 'Date',
                'value' => $date->format('Y-m-d H:i:s T'),
                'full' => $date->format('r'),
            ];
        }

        // Message-ID
        $messageId = $email->getMessageId();
        if ($messageId) {
            $headers['message_id'] = [
                'label' => 'Message-ID',
                'value' => $messageId,
                'full' => $messageId,
            ];
        }

        // X-Mailer
        $mailer = $email->getMailer();
        if ($mailer) {
            $headers['x_mailer'] = [
                'label' => 'X-Mailer',
                'value' => $mailer,
                'full' => $mailer,
            ];
        }

        // X-Originating-IP
        $originatingIp = $email->getOriginatingIp();
        if ($originatingIp) {
            $headers['x_originating_ip'] = [
                'label' => 'X-Originating-IP',
                'value' => $originatingIp,
                'full' => $originatingIp,
            ];
        }

        // Authentication-Results
        $authResults = $email->getAuthenticationResults();
        if ($authResults) {
            $headers['authentication_results'] = [
                'label' => 'Authentication-Results',
                'value' => $authResults,
                'full' => $authResults,
            ];
        }

        // Received headers (routing path)
        $received = $email->getReceivedHeaders();
        if (!empty($received)) {
            $headers['received'] = [
                'label' => 'Received',
                'value' => count($received) . ' hop(s)',
                'hops' => $received,
                'full' => implode("\n", $received),
            ];
        }

        return $headers;
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

        // Track authentication check statuses
        $authStatus = [
            'spf' => null,
            'dkim' => null,
            'dmarc' => null,
        ];

        // Track other critical failures
        $criticalFailures = [];

        foreach ($results as $result) {
            $checkType = $result['check_type'];
            $status = $result['status'];

            // Track SPF/DKIM/DMARC statuses
            if (in_array($checkType, ['spf', 'dkim', 'dmarc'])) {
                $authStatus[$checkType] = $status;
            }

            // VirusTotal malicious detection = automatic high risk
            if (in_array($checkType, ['virustotal_url', 'virustotal_file']) && $status === 'fail') {
                $criticalFailures[] = 'VirusTotal';
            }

            // Check header analysis for authentication failures from email's Authentication-Results
            if ($checkType === 'header' && !empty($result['details']['findings'])) {
                foreach ($result['details']['findings'] as $finding) {
                    $findingType = $finding['type'] ?? '';
                    $severity = $finding['severity'] ?? '';

                    // SPF failure in Authentication-Results (overrides DNS check)
                    if ($findingType === 'spf_failure' && $severity === 'high') {
                        $authStatus['spf'] = 'fail';
                    }

                    // DKIM failure in Authentication-Results (overrides DNS check)
                    if ($findingType === 'dkim_failure' && $severity === 'high') {
                        $authStatus['dkim'] = 'fail';
                    }

                    // DMARC failure in Authentication-Results = automatic high risk
                    if ($findingType === 'dmarc_failure' && $severity === 'high') {
                        $authStatus['dmarc'] = 'fail';
                        $criticalFailures[] = 'DMARC (Authentication-Results)';
                    }

                    // Display name spoofing = high risk
                    if ($findingType === 'display_name_spoofing') {
                        $criticalFailures[] = 'Display name spoofing';
                    }
                }
            }
        }

        // Calculate base score from weighted factors
        $baseScore = $this->calculateWeightedScore($results);

        // Determine authentication-based risk level
        $spfPass = $authStatus['spf'] === 'pass';
        $dkimPass = $authStatus['dkim'] === 'pass';
        $dmarcPass = $authStatus['dmarc'] === 'pass';
        $spfFail = $authStatus['spf'] === 'fail';
        $dkimFail = $authStatus['dkim'] === 'fail';
        $dmarcFail = $authStatus['dmarc'] === 'fail';

        // All three fail = automatic high risk (minimum 65)
        if ($spfFail && $dkimFail && $dmarcFail) {
            $this->logger->info('All authentication checks failed - high risk', [
                'scan_id' => $scanId,
                'spf' => $authStatus['spf'],
                'dkim' => $authStatus['dkim'],
                'dmarc' => $authStatus['dmarc'],
            ]);
            return max(65, $baseScore);
        }

        // SPF pass + DMARC pass + DKIM fail = automatic medium risk (minimum 40)
        if ($spfPass && $dmarcPass && $dkimFail) {
            $this->logger->info('DKIM failed with SPF/DMARC pass - medium risk', [
                'scan_id' => $scanId,
                'spf' => $authStatus['spf'],
                'dkim' => $authStatus['dkim'],
                'dmarc' => $authStatus['dmarc'],
            ]);
            return max(40, $baseScore);
        }

        // DKIM pass + DMARC pass + SPF fail = automatic medium risk (minimum 40)
        if ($dkimPass && $dmarcPass && $spfFail) {
            $this->logger->info('SPF failed with DKIM/DMARC pass - medium risk', [
                'scan_id' => $scanId,
                'spf' => $authStatus['spf'],
                'dkim' => $authStatus['dkim'],
                'dmarc' => $authStatus['dmarc'],
            ]);
            return max(40, $baseScore);
        }

        // Other critical failures (VirusTotal, display name spoofing) = high risk
        if (!empty($criticalFailures)) {
            $this->logger->info('Critical failures detected - high risk', [
                'scan_id' => $scanId,
                'failures' => array_unique($criticalFailures),
            ]);
            return max(65, $baseScore);
        }

        return $baseScore;
    }

    /**
     * Calculate weighted risk score from results
     */
    private function calculateWeightedScore(array $results): int
    {
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

    /**
     * Update individual URL scan in VirusTotal results
     */
    public function updateIndividualUrlScan(int $scanId, string $url, array $vtResult): void
    {
        $this->logger->info('Updating individual URL scan', ['scan_id' => $scanId, 'url' => $url]);

        try {
            // Get existing virustotal_url result
            $results = $this->resultModel->getByScanId($scanId);
            $vtUrlResult = null;
            $vtUrlResultId = null;

            foreach ($results as $result) {
                if ($result['check_type'] === 'virustotal_url') {
                    $vtUrlResult = $result;
                    $vtUrlResultId = $result['id'];
                    break;
                }
            }

            // Prepare new URL entry
            $newEntry = [
                'url' => $url,
                'result' => $vtResult,
                'scanned_individually' => true,
                'scanned_at' => date('Y-m-d H:i:s'),
            ];

            $existingResults = [];
            $urlFound = false;

            if ($vtUrlResult && !empty($vtUrlResult['details']['results'])) {
                $existingResults = $vtUrlResult['details']['results'];

                // Update existing entry or add new one
                foreach ($existingResults as $key => $entry) {
                    if (($entry['url'] ?? '') === $url) {
                        $existingResults[$key] = $newEntry;
                        $urlFound = true;
                        break;
                    }
                }
            }

            if (!$urlFound) {
                $existingResults[] = $newEntry;
            }

            // Count malicious URLs
            $maliciousCount = 0;
            foreach ($existingResults as $entry) {
                if (isset($entry['result']['stats']['malicious']) && $entry['result']['stats']['malicious'] > 0) {
                    $maliciousCount++;
                }
            }

            // Determine status and score
            $status = $maliciousCount > 0 ? 'fail' : 'pass';
            $score = $maliciousCount > 0 ? 0 : 100;
            $summary = "Scanned " . count($existingResults) . " URL(s), $maliciousCount flagged";

            // Update or create result
            if ($vtUrlResultId) {
                $this->resultModel->update($vtUrlResultId, [
                    'status' => $status,
                    'score' => $score,
                    'summary' => $summary,
                    'details' => ['results' => $existingResults],
                ]);
            } else {
                $this->resultModel->create([
                    'scan_id' => $scanId,
                    'check_type' => 'virustotal_url',
                    'status' => $status,
                    'score' => $score,
                    'summary' => $summary,
                    'details' => ['results' => $existingResults],
                ]);
            }

            // Also update the individual URL's risk level in the links result
            $this->updateLinkRiskLevel($scanId, $url, $vtResult);

            $this->logger->info('Individual URL scan updated', [
                'scan_id' => $scanId,
                'url' => $url,
                'malicious' => $maliciousCount,
                'total' => count($existingResults),
            ]);
        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Failed to update individual URL scan', ['scan_id' => $scanId, 'url' => $url]);
            throw $e;
        }
    }

    /**
     * Update individual link's risk level based on VirusTotal results
     */
    private function updateLinkRiskLevel(int $scanId, string $url, array $vtResult): void
    {
        try {
            // Get the links result
            $results = $this->resultModel->getByScanId($scanId);
            $linksResult = null;
            $linksResultId = null;

            foreach ($results as $result) {
                if ($result['check_type'] === 'links') {
                    $linksResult = $result;
                    $linksResultId = $result['id'];
                    break;
                }
            }

            if (!$linksResult || empty($linksResult['details']['links'])) {
                $this->logger->warning('No links result found to update', ['scan_id' => $scanId]);
                return;
            }

            // Update the specific link's risk level
            $links = $linksResult['details']['links'];
            $linkUpdated = false;

            foreach ($links as $key => $link) {
                if ($link['url'] === $url) {
                    $malicious = $vtResult['stats']['malicious'] ?? 0;
                    $suspicious = $vtResult['stats']['suspicious'] ?? 0;

                    // Determine new risk level based on VT results
                    if ($malicious > 0) {
                        $links[$key]['risk_level'] = 'high';
                        $links[$key]['score'] = 100; // Maximum risk score
                    } elseif ($suspicious > 0) {
                        $links[$key]['risk_level'] = 'medium';
                        $links[$key]['score'] = 50;
                    } else {
                        // Clean
                        $links[$key]['risk_level'] = 'low';
                        $links[$key]['score'] = 0; // Minimal risk
                    }

                    $links[$key]['vt_scanned'] = true;
                    $linkUpdated = true;
                    $this->logger->info('Link risk level updated', [
                        'url' => $url,
                        'new_risk_level' => $links[$key]['risk_level'],
                        'malicious' => $malicious,
                        'suspicious' => $suspicious,
                    ]);
                    break;
                }
            }

            if ($linkUpdated) {
                // Recalculate summary stats
                $suspiciousCount = 0;
                $maxScore = 0;

                foreach ($links as $link) {
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

                // Update the links result
                $this->resultModel->update($linksResultId, [
                    'status' => $status,
                    'score' => 100 - $maxScore,
                    'summary' => count($links) . ' link(s) found, ' . $suspiciousCount . ' suspicious',
                    'details' => array_merge($linksResult['details'], ['links' => $links]),
                ]);

                $this->logger->info('Links result updated', [
                    'scan_id' => $scanId,
                    'max_score' => $maxScore,
                    'suspicious_count' => $suspiciousCount,
                ]);
            }
        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Failed to update link risk level', ['scan_id' => $scanId, 'url' => $url]);
            // Don't throw - this is not critical enough to fail the whole operation
        }
    }

    /**
     * Recalculate risk score for a scan
     */
    public function recalculateRiskScore(int $scanId): void
    {
        $this->logger->info('Recalculating risk score', ['scan_id' => $scanId]);

        try {
            $riskScore = $this->calculateRiskScore($scanId);
            $this->scanModel->update($scanId, ['risk_score' => $riskScore]);

            $this->logger->info('Risk score recalculated', ['scan_id' => $scanId, 'risk_score' => $riskScore]);
        } catch (\Throwable $e) {
            $this->logger->exception($e, 'Failed to recalculate risk score', ['scan_id' => $scanId]);
            throw $e;
        }
    }
}
