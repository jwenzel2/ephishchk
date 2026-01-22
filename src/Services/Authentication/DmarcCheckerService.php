<?php

declare(strict_types=1);

namespace Ephishchk\Services\Authentication;

/**
 * DMARC Record Checker Service
 */
class DmarcCheckerService
{
    private DnsLookupService $dns;

    public function __construct(DnsLookupService $dns)
    {
        $this->dns = $dns;
    }

    /**
     * Check DMARC record for a domain
     *
     * @return array{status: string, record: ?string, details: array}
     */
    public function check(string $domain): array
    {
        $record = $this->dns->getDmarcRecord($domain);

        if ($record === null) {
            // Check for organizational domain DMARC
            $orgDomain = $this->getOrganizationalDomain($domain);
            if ($orgDomain !== $domain) {
                $record = $this->dns->getDmarcRecord($orgDomain);
                if ($record !== null) {
                    return $this->analyzeRecord($record, $domain, $orgDomain);
                }
            }

            return [
                'status' => 'fail',
                'record' => null,
                'details' => [
                    'error' => 'No DMARC record found',
                    'recommendation' => 'Add a DMARC record to protect your domain from spoofing',
                    'example' => 'v=DMARC1; p=reject; rua=mailto:dmarc@' . $domain,
                ],
            ];
        }

        return $this->analyzeRecord($record, $domain);
    }

    /**
     * Analyze a DMARC record
     */
    private function analyzeRecord(string $record, string $domain, ?string $orgDomain = null): array
    {
        $parsed = $this->parseDmarcRecord($record);
        $issues = $this->validateDmarc($parsed);

        $status = 'pass';
        if (!empty($issues['errors'])) {
            $status = 'fail';
        } elseif (!empty($issues['warnings'])) {
            $status = 'warning';
        }

        $details = [
            'parsed' => $parsed,
            'issues' => $issues,
            'recommendation' => $this->getRecommendation($parsed, $issues),
        ];

        if ($orgDomain !== null) {
            $details['note'] = "Using organizational domain DMARC: _dmarc.$orgDomain";
        }

        return [
            'status' => $status,
            'record' => $record,
            'details' => $details,
        ];
    }

    /**
     * Parse DMARC record into components
     */
    public function parseDmarcRecord(string $record): array
    {
        $parsed = [
            'version' => null,
            'policy' => null,
            'subdomain_policy' => null,
            'percentage' => 100,
            'rua' => [],
            'ruf' => [],
            'adkim' => 'r', // Default: relaxed
            'aspf' => 'r', // Default: relaxed
            'fo' => '0', // Default: generate reports on all failures
            'rf' => 'afrf', // Default: Authentication Failure Reporting Format
            'ri' => 86400, // Default: 86400 seconds (1 day)
        ];

        // Split record into tag=value pairs
        $parts = preg_split('/;\s*/', trim($record));

        foreach ($parts as $part) {
            $part = trim($part);
            if (empty($part)) {
                continue;
            }

            if (!str_contains($part, '=')) {
                continue;
            }

            [$tag, $value] = explode('=', $part, 2);
            $tag = trim(strtolower($tag));
            $value = trim($value);

            switch ($tag) {
                case 'v':
                    $parsed['version'] = $value;
                    break;
                case 'p':
                    $parsed['policy'] = strtolower($value);
                    break;
                case 'sp':
                    $parsed['subdomain_policy'] = strtolower($value);
                    break;
                case 'pct':
                    $parsed['percentage'] = (int) $value;
                    break;
                case 'rua':
                    $parsed['rua'] = $this->parseReportingAddresses($value);
                    break;
                case 'ruf':
                    $parsed['ruf'] = $this->parseReportingAddresses($value);
                    break;
                case 'adkim':
                    $parsed['adkim'] = strtolower($value);
                    break;
                case 'aspf':
                    $parsed['aspf'] = strtolower($value);
                    break;
                case 'fo':
                    $parsed['fo'] = $value;
                    break;
                case 'rf':
                    $parsed['rf'] = strtolower($value);
                    break;
                case 'ri':
                    $parsed['ri'] = (int) $value;
                    break;
            }
        }

        return $parsed;
    }

    /**
     * Parse comma-separated reporting addresses
     */
    private function parseReportingAddresses(string $value): array
    {
        $addresses = [];
        $parts = explode(',', $value);

        foreach ($parts as $part) {
            $part = trim($part);
            if (!empty($part)) {
                $addresses[] = $part;
            }
        }

        return $addresses;
    }

    /**
     * Validate DMARC record
     */
    private function validateDmarc(array $parsed): array
    {
        $errors = [];
        $warnings = [];
        $info = [];

        // Check version
        if ($parsed['version'] !== 'DMARC1') {
            $errors[] = 'Invalid or missing DMARC version (must be v=DMARC1)';
        }

        // Check policy
        if ($parsed['policy'] === null) {
            $errors[] = 'Missing policy (p=) - required tag';
        } elseif (!in_array($parsed['policy'], ['none', 'quarantine', 'reject'])) {
            $errors[] = 'Invalid policy: ' . $parsed['policy'];
        } elseif ($parsed['policy'] === 'none') {
            $warnings[] = 'Policy is set to "none" - emails failing DMARC will not be blocked';
            $info[] = 'Monitor-only mode is useful during initial deployment';
        } elseif ($parsed['policy'] === 'quarantine') {
            $info[] = 'Policy is set to "quarantine" - failing emails may be marked as spam';
        } elseif ($parsed['policy'] === 'reject') {
            $info[] = 'Policy is set to "reject" - maximum protection against spoofing';
        }

        // Check subdomain policy
        if ($parsed['subdomain_policy'] === null) {
            $info[] = 'No subdomain policy (sp=) - inherits main policy';
        }

        // Check percentage
        if ($parsed['percentage'] < 100) {
            $warnings[] = 'Policy applies to only ' . $parsed['percentage'] . '% of messages';
        }

        // Check reporting
        if (empty($parsed['rua'])) {
            $warnings[] = 'No aggregate report recipients (rua=) - you won\'t receive DMARC reports';
        } else {
            $info[] = 'Aggregate reports will be sent to: ' . implode(', ', $parsed['rua']);
        }

        // Check alignment modes
        if ($parsed['adkim'] === 's') {
            $info[] = 'Strict DKIM alignment required';
        }
        if ($parsed['aspf'] === 's') {
            $info[] = 'Strict SPF alignment required';
        }

        return [
            'errors' => $errors,
            'warnings' => $warnings,
            'info' => $info,
            'policy_strength' => $this->getPolicyStrength($parsed),
        ];
    }

    /**
     * Get policy strength rating
     */
    private function getPolicyStrength(array $parsed): array
    {
        $strength = 0;
        $factors = [];

        // Policy
        if ($parsed['policy'] === 'reject') {
            $strength += 40;
            $factors[] = 'Strong policy (reject)';
        } elseif ($parsed['policy'] === 'quarantine') {
            $strength += 25;
            $factors[] = 'Medium policy (quarantine)';
        } elseif ($parsed['policy'] === 'none') {
            $strength += 5;
            $factors[] = 'Weak policy (none/monitor)';
        }

        // Percentage
        if ($parsed['percentage'] === 100) {
            $strength += 20;
            $factors[] = 'Full coverage (100%)';
        } else {
            $strength += (int) ($parsed['percentage'] * 0.2);
            $factors[] = 'Partial coverage (' . $parsed['percentage'] . '%)';
        }

        // Alignment
        if ($parsed['adkim'] === 's') {
            $strength += 10;
            $factors[] = 'Strict DKIM alignment';
        } else {
            $strength += 5;
        }

        if ($parsed['aspf'] === 's') {
            $strength += 10;
            $factors[] = 'Strict SPF alignment';
        } else {
            $strength += 5;
        }

        // Reporting
        if (!empty($parsed['rua'])) {
            $strength += 10;
            $factors[] = 'Reporting enabled';
        }

        // Subdomain policy
        if ($parsed['subdomain_policy'] === 'reject') {
            $strength += 10;
            $factors[] = 'Strong subdomain policy';
        }

        return [
            'score' => min(100, $strength),
            'factors' => $factors,
        ];
    }

    /**
     * Get organizational domain (simplified public suffix handling)
     */
    private function getOrganizationalDomain(string $domain): string
    {
        $parts = explode('.', $domain);

        if (count($parts) <= 2) {
            return $domain;
        }

        // Simple heuristic: return last 2 parts
        // A proper implementation would use the Public Suffix List
        return implode('.', array_slice($parts, -2));
    }

    /**
     * Get recommendation based on DMARC analysis
     */
    private function getRecommendation(array $parsed, array $issues): string
    {
        if (!empty($issues['errors'])) {
            return 'Fix the DMARC record errors to enable proper email authentication';
        }

        if ($parsed['policy'] === 'none') {
            return 'Consider upgrading to p=quarantine or p=reject after monitoring reports';
        }

        if ($parsed['policy'] === 'quarantine' && $parsed['percentage'] === 100) {
            return 'Consider upgrading to p=reject for maximum protection';
        }

        if (empty($parsed['rua'])) {
            return 'Add rua= to receive aggregate reports and monitor DMARC effectiveness';
        }

        if ($parsed['policy'] === 'reject' && $parsed['percentage'] === 100) {
            return 'DMARC is configured with maximum protection';
        }

        return 'DMARC is configured and functional';
    }

    /**
     * Get human-readable policy description
     */
    public function getPolicyDescription(string $policy): string
    {
        return match ($policy) {
            'none' => 'Monitor only - no action taken on failing emails',
            'quarantine' => 'Suspicious - failing emails may be marked as spam',
            'reject' => 'Reject - failing emails will be blocked',
            default => 'Unknown policy',
        };
    }
}
