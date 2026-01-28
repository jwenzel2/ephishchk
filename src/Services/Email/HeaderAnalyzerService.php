<?php

declare(strict_types=1);

namespace Ephishchk\Services\Email;

use Ephishchk\Services\Scanner\TyposquattingDetectionService;

/**
 * Email Header Analyzer Service - detects suspicious patterns
 */
class HeaderAnalyzerService
{
    private array $suspiciousPatterns = [];
    private ?TyposquattingDetectionService $typosquattingDetector = null;
    private array $safeDomains = [];

    public function __construct(
        array $config = [],
        ?TyposquattingDetectionService $typosquattingDetector = null
    ) {
        $this->suspiciousPatterns = $config['suspicious_patterns'] ?? [
            'x_originating_ip_mismatch' => true,
            'authentication_failures' => true,
            'unusual_routing' => true,
            'domain_mismatch' => true,
        ];
        $this->typosquattingDetector = $typosquattingDetector;
    }

    /**
     * Set safe domains for typosquatting detection
     */
    public function setSafeDomains(array $domains): void
    {
        $this->safeDomains = $domains;
    }

    /**
     * Analyze email headers for suspicious patterns
     *
     * @return array{score: int, findings: array}
     */
    public function analyze(ParsedEmail $email): array
    {
        $findings = [];
        $score = 0;

        // Check for domain mismatches
        if ($this->suspiciousPatterns['domain_mismatch']) {
            $domainFindings = $this->checkDomainMismatches($email);
            $findings = array_merge($findings, $domainFindings['findings']);
            $score += $domainFindings['score'];
        }

        // Check authentication failures in headers
        if ($this->suspiciousPatterns['authentication_failures']) {
            $authFindings = $this->checkAuthenticationResults($email);
            $findings = array_merge($findings, $authFindings['findings']);
            $score += $authFindings['score'];
        }

        // Check received headers for unusual routing
        if ($this->suspiciousPatterns['unusual_routing']) {
            $routingFindings = $this->checkReceivedHeaders($email);
            $findings = array_merge($findings, $routingFindings['findings']);
            $score += $routingFindings['score'];
        }

        // Check for suspicious header patterns
        $patternFindings = $this->checkSuspiciousPatterns($email);
        $findings = array_merge($findings, $patternFindings['findings']);
        $score += $patternFindings['score'];

        // Check for typosquatting in header domains
        if ($this->typosquattingDetector && !empty($this->safeDomains)) {
            $typosquattingFindings = $this->checkHeaderTyposquatting($email);
            $findings = array_merge($findings, $typosquattingFindings['findings']);
            $score += $typosquattingFindings['score'];
        }

        // Normalize score to 0-100
        $score = min(100, max(0, $score));

        return [
            'score' => $score,
            'findings' => $findings,
            'summary' => $this->generateSummary($findings, $score),
        ];
    }

    /**
     * Check for domain mismatches between From, Return-Path, etc.
     */
    private function checkDomainMismatches(ParsedEmail $email): array
    {
        $findings = [];
        $score = 0;

        $from = $email->getFrom();
        $returnPath = $email->getReturnPath();
        $replyTo = $email->getReplyTo();

        $fromDomain = $from ? $this->extractDomain($from['email'] ?? '') : null;
        $returnPathDomain = $returnPath ? $this->extractDomain($returnPath) : null;
        $replyToDomain = $replyTo ? $this->extractDomain($replyTo['email'] ?? '') : null;

        // Check From vs Return-Path
        if ($fromDomain && $returnPathDomain && $fromDomain !== $returnPathDomain) {
            $isRelated = $this->areDomainsRelated($fromDomain, $returnPathDomain);
            if (!$isRelated) {
                $findings[] = [
                    'type' => 'domain_mismatch',
                    'severity' => 'warning',
                    'message' => "From domain ($fromDomain) differs from Return-Path domain ($returnPathDomain)",
                    'details' => 'Different domains may indicate email forwarding or potential spoofing',
                ];
                $score += 15;
            }
        }

        // Check From vs Reply-To
        if ($fromDomain && $replyToDomain && $fromDomain !== $replyToDomain) {
            $isRelated = $this->areDomainsRelated($fromDomain, $replyToDomain);
            if (!$isRelated) {
                $findings[] = [
                    'type' => 'domain_mismatch',
                    'severity' => 'warning',
                    'message' => "From domain ($fromDomain) differs from Reply-To domain ($replyToDomain)",
                    'details' => 'Replies will go to a different domain - verify this is expected',
                ];
                $score += 20;
            }
        }

        // Check for display name spoofing
        if ($from && !empty($from['name']) && !empty($from['email'])) {
            $nameEmail = $this->extractEmailFromName($from['name']);
            if ($nameEmail && strtolower($nameEmail) !== strtolower($from['email'])) {
                $findings[] = [
                    'type' => 'display_name_spoofing',
                    'severity' => 'high',
                    'message' => 'Display name contains a different email address',
                    'details' => "Name: {$from['name']}, Actual email: {$from['email']}",
                ];
                $score += 30;
            }
        }

        return ['findings' => $findings, 'score' => $score];
    }

    /**
     * Check Authentication-Results header
     */
    private function checkAuthenticationResults(ParsedEmail $email): array
    {
        $findings = [];
        $score = 0;

        $authResults = $email->getAuthenticationResults();
        if (!$authResults) {
            $findings[] = [
                'type' => 'missing_auth_results',
                'severity' => 'info',
                'message' => 'No Authentication-Results header found',
                'details' => 'This header is added by receiving mail servers',
            ];
            return ['findings' => $findings, 'score' => $score];
        }

        // Parse authentication results
        $results = $this->parseAuthenticationResults($authResults);

        // Check SPF result
        if (isset($results['spf'])) {
            if ($results['spf'] === 'fail' || $results['spf'] === 'softfail') {
                $findings[] = [
                    'type' => 'spf_failure',
                    'severity' => $results['spf'] === 'fail' ? 'high' : 'warning',
                    'message' => 'SPF check ' . $results['spf'],
                    'details' => 'The sending server may not be authorized to send for this domain',
                ];
                $score += $results['spf'] === 'fail' ? 25 : 15;
            }
        }

        // Check DKIM result
        if (isset($results['dkim'])) {
            if ($results['dkim'] === 'fail') {
                $findings[] = [
                    'type' => 'dkim_failure',
                    'severity' => 'high',
                    'message' => 'DKIM signature verification failed',
                    'details' => 'The email may have been modified in transit or is forged',
                ];
                $score += 25;
            }
        }

        // Check DMARC result
        if (isset($results['dmarc'])) {
            if ($results['dmarc'] === 'fail') {
                $findings[] = [
                    'type' => 'dmarc_failure',
                    'severity' => 'high',
                    'message' => 'DMARC check failed',
                    'details' => 'Email failed domain alignment checks',
                ];
                $score += 30;
            }
        }

        return ['findings' => $findings, 'score' => $score];
    }

    /**
     * Analyze Received headers for unusual routing
     */
    private function checkReceivedHeaders(ParsedEmail $email): array
    {
        $findings = [];
        $score = 0;

        $receivedHeaders = $email->getReceivedHeaders();

        if (empty($receivedHeaders)) {
            $findings[] = [
                'type' => 'missing_received',
                'severity' => 'warning',
                'message' => 'No Received headers found',
                'details' => 'Legitimate emails typically have Received headers from mail servers',
            ];
            $score += 20;
            return ['findings' => $findings, 'score' => $score];
        }

        // Check number of hops
        $hopCount = count($receivedHeaders);
        if ($hopCount > 10) {
            $findings[] = [
                'type' => 'excessive_hops',
                'severity' => 'info',
                'message' => "Email passed through $hopCount mail servers",
                'details' => 'Unusually high number of hops may indicate mail forwarding or routing issues',
            ];
        }

        // Look for suspicious patterns in received headers
        foreach ($receivedHeaders as $i => $header) {
            // Check for localhost/internal IPs in early hops
            if ($i > 0 && preg_match('/\b(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)\b/i', $header)) {
                // This is normal for early hops from internal servers
            }

            // Check for suspicious "with" clauses
            if (preg_match('/with\s+(SMTP|ESMTP)\s/i', $header) && !preg_match('/with\s+(SMTP|ESMTP)(S|A|SA)?\s/i', $header)) {
                // Plain SMTP without TLS
                $findings[] = [
                    'type' => 'unencrypted_hop',
                    'severity' => 'info',
                    'message' => 'Email passed through unencrypted SMTP hop',
                    'details' => "Hop " . ($i + 1) . " used unencrypted SMTP",
                ];
            }
        }

        return ['findings' => $findings, 'score' => $score];
    }

    /**
     * Check for other suspicious patterns
     */
    private function checkSuspiciousPatterns(ParsedEmail $email): array
    {
        $findings = [];
        $score = 0;

        // Check X-Mailer for suspicious clients
        $mailer = $email->getMailer();
        if ($mailer) {
            $suspiciousMailers = ['Mass Mailer', 'Bulk Mailer', 'PHPMailer'];
            foreach ($suspiciousMailers as $sm) {
                if (stripos($mailer, $sm) !== false) {
                    $findings[] = [
                        'type' => 'suspicious_mailer',
                        'severity' => 'info',
                        'message' => "Email sent using: $mailer",
                        'details' => 'This mail client is sometimes used for bulk/spam emails',
                    ];
                    $score += 5;
                    break;
                }
            }
        }

        // Check for missing Message-ID
        if (!$email->getMessageId()) {
            $findings[] = [
                'type' => 'missing_message_id',
                'severity' => 'warning',
                'message' => 'No Message-ID header found',
                'details' => 'Legitimate emails typically have a Message-ID',
            ];
            $score += 10;
        }

        // Check for missing Date
        if (!$email->getDate()) {
            $findings[] = [
                'type' => 'missing_date',
                'severity' => 'warning',
                'message' => 'No Date header found',
                'details' => 'Legitimate emails always have a Date header',
            ];
            $score += 10;
        }

        // Check subject for common phishing patterns
        $subject = $email->getSubject() ?? '';
        $phishingSubjectPatterns = [
            '/urgent.*action/i',
            '/verify.*account/i',
            '/suspended.*account/i',
            '/unusual.*activity/i',
            '/security.*alert/i',
            '/password.*expire/i',
            '/won.*prize/i',
            '/claim.*reward/i',
        ];

        foreach ($phishingSubjectPatterns as $pattern) {
            if (preg_match($pattern, $subject)) {
                $findings[] = [
                    'type' => 'suspicious_subject',
                    'severity' => 'warning',
                    'message' => 'Subject contains common phishing keywords',
                    'details' => "Subject: $subject",
                ];
                $score += 10;
                break;
            }
        }

        return ['findings' => $findings, 'score' => $score];
    }

    /**
     * Check header domains for typosquatting attempts against safe domains
     */
    private function checkHeaderTyposquatting(ParsedEmail $email): array
    {
        error_log("[HeaderAnalyzer] Starting typosquatting checks for header domains");
        error_log("[HeaderAnalyzer] Safe domains count: " . count($this->safeDomains));

        $findings = [];
        $score = 0;

        // Extract header domains
        $headerDomains = [
            'from' => null,
            'reply_to' => null,
            'return_path' => null,
        ];

        $from = $email->getFrom();
        if ($from && isset($from['email'])) {
            $headerDomains['from'] = $this->extractDomain($from['email']);
        }

        $replyTo = $email->getReplyTo();
        if ($replyTo && isset($replyTo['email'])) {
            $headerDomains['reply_to'] = $this->extractDomain($replyTo['email']);
        }

        $returnPath = $email->getReturnPath();
        if ($returnPath) {
            $headerDomains['return_path'] = $this->extractDomain($returnPath);
        }

        // Check each domain against safe domains list
        foreach ($headerDomains as $headerField => $domain) {
            if (!$domain) {
                continue;
            }

            error_log("[HeaderAnalyzer] Checking $headerField domain: $domain");
            $finding = $this->typosquattingDetector->checkDomainAgainstSafeList($domain, $this->safeDomains);
            if ($finding) {
                error_log("[HeaderAnalyzer] ✓ Typosquatting finding for $headerField: {$finding['matched_safe_domain']}");
                // Add header field identifier to the finding
                $finding['header_field'] = $headerField;
                $findings[] = $finding;
                $score += 40;
            }
        }

        return ['findings' => $findings, 'score' => $score];
    }

    /**
     * Parse Authentication-Results header into components
     */
    private function parseAuthenticationResults(string $header): array
    {
        $results = [];

        // Look for spf=, dkim=, dmarc= patterns
        if (preg_match('/\bspf=(\w+)/i', $header, $matches)) {
            $results['spf'] = strtolower($matches[1]);
        }

        if (preg_match('/\bdkim=(\w+)/i', $header, $matches)) {
            $results['dkim'] = strtolower($matches[1]);
        }

        if (preg_match('/\bdmarc=(\w+)/i', $header, $matches)) {
            $results['dmarc'] = strtolower($matches[1]);
        }

        return $results;
    }

    /**
     * Extract domain from email address
     */
    private function extractDomain(string $email): ?string
    {
        if (empty($email)) {
            return null;
        }

        $parts = explode('@', $email);
        return count($parts) === 2 ? strtolower($parts[1]) : null;
    }

    /**
     * Check if two domains are related (same org domain)
     */
    private function areDomainsRelated(string $domain1, string $domain2): bool
    {
        if ($domain1 === $domain2) {
            return true;
        }

        // Check if one is subdomain of other
        if (str_ends_with($domain1, '.' . $domain2) || str_ends_with($domain2, '.' . $domain1)) {
            return true;
        }

        // Get base domains (simplified)
        $base1 = $this->getBaseDomain($domain1);
        $base2 = $this->getBaseDomain($domain2);

        return $base1 === $base2;
    }

    /**
     * Get base domain (simplified, doesn't use PSL)
     */
    private function getBaseDomain(string $domain): string
    {
        $parts = explode('.', $domain);
        if (count($parts) <= 2) {
            return $domain;
        }
        return implode('.', array_slice($parts, -2));
    }

    /**
     * Extract email address from display name (detect spoofing)
     */
    private function extractEmailFromName(string $name): ?string
    {
        // Look for email pattern in name
        if (preg_match('/[\w.+-]+@[\w.-]+\.\w+/', $name, $matches)) {
            return $matches[0];
        }
        return null;
    }

    /**
     * Generate human-readable summary
     */
    private function generateSummary(array $findings, int $score): string
    {
        $highCount = 0;
        $warningCount = 0;

        foreach ($findings as $finding) {
            if ($finding['severity'] === 'high') {
                $highCount++;
            } elseif ($finding['severity'] === 'warning') {
                $warningCount++;
            }
        }

        if ($score >= 50) {
            return "High risk: $highCount critical issues and $warningCount warnings found";
        } elseif ($score >= 25) {
            return "Medium risk: $warningCount warnings found in email headers";
        } elseif ($highCount === 0 && $warningCount === 0) {
            return 'No suspicious patterns detected in email headers';
        } else {
            return 'Low risk: Minor issues found in email headers';
        }
    }
}
