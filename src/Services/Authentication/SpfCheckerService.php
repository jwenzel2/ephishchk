<?php

declare(strict_types=1);

namespace Ephishchk\Services\Authentication;

/**
 * SPF Record Checker Service
 */
class SpfCheckerService
{
    private DnsLookupService $dns;

    public function __construct(DnsLookupService $dns)
    {
        $this->dns = $dns;
    }

    /**
     * Check SPF record for a domain
     *
     * @return array{status: string, record: ?string, details: array}
     */
    public function check(string $domain): array
    {
        $record = $this->dns->getSpfRecord($domain);

        if ($record === null) {
            return [
                'status' => 'fail',
                'record' => null,
                'details' => [
                    'error' => 'No SPF record found',
                    'recommendation' => 'Add an SPF record to specify authorized mail servers',
                ],
            ];
        }

        $parsed = $this->parseSpfRecord($record);
        $issues = $this->validateSpf($parsed, $domain);

        $status = 'pass';
        if (!empty($issues['errors'])) {
            $status = 'fail';
        } elseif (!empty($issues['warnings'])) {
            $status = 'warning';
        }

        return [
            'status' => $status,
            'record' => $record,
            'details' => [
                'parsed' => $parsed,
                'issues' => $issues,
                'recommendation' => $this->getRecommendation($parsed, $issues),
            ],
        ];
    }

    /**
     * Parse SPF record into components
     */
    public function parseSpfRecord(string $record): array
    {
        $parsed = [
            'version' => null,
            'mechanisms' => [],
            'modifiers' => [],
            'all' => null,
        ];

        // Split record into parts
        $parts = preg_split('/\s+/', trim($record));

        foreach ($parts as $part) {
            // Version
            if (str_starts_with($part, 'v=')) {
                $parsed['version'] = substr($part, 2);
                continue;
            }

            // Modifiers (redirect=, exp=)
            if (str_contains($part, '=')) {
                [$name, $value] = explode('=', $part, 2);
                $parsed['modifiers'][$name] = $value;
                continue;
            }

            // Parse qualifier and mechanism
            $qualifier = '+'; // Default is pass
            if (in_array($part[0], ['+', '-', '~', '?'])) {
                $qualifier = $part[0];
                $part = substr($part, 1);
            }

            // "all" mechanism
            if ($part === 'all') {
                $parsed['all'] = $qualifier;
                continue;
            }

            // Other mechanisms
            $mechanism = [
                'qualifier' => $qualifier,
                'type' => null,
                'value' => null,
            ];

            if (str_contains($part, ':')) {
                [$type, $value] = explode(':', $part, 2);
                $mechanism['type'] = $type;
                $mechanism['value'] = $value;
            } elseif (str_contains($part, '/')) {
                // IP with CIDR
                $mechanism['type'] = str_starts_with($part, 'ip6:') ? 'ip6' : 'ip4';
                $mechanism['value'] = $part;
            } else {
                $mechanism['type'] = $part;
            }

            $parsed['mechanisms'][] = $mechanism;
        }

        return $parsed;
    }

    /**
     * Validate SPF record and return issues
     */
    private function validateSpf(array $parsed, string $domain): array
    {
        $errors = [];
        $warnings = [];
        $info = [];

        // Check version
        if ($parsed['version'] !== 'spf1') {
            $errors[] = 'Invalid or missing SPF version (should be v=spf1)';
        }

        // Check for "all" mechanism
        if ($parsed['all'] === null) {
            $warnings[] = 'No "all" mechanism found - SPF evaluation may be unpredictable';
        } elseif ($parsed['all'] === '+') {
            $errors[] = 'Using +all allows any server to send mail - this defeats SPF protection';
        } elseif ($parsed['all'] === '?') {
            $warnings[] = 'Using ?all (neutral) provides weak protection';
        } elseif ($parsed['all'] === '~') {
            $info[] = 'Using ~all (softfail) - emails may be marked as spam but not rejected';
        } elseif ($parsed['all'] === '-') {
            $info[] = 'Using -all (hardfail) - recommended for strict SPF enforcement';
        }

        // Count DNS lookups
        $dnsLookups = $this->countDnsLookups($parsed);
        if ($dnsLookups > 10) {
            $errors[] = "Too many DNS lookups ($dnsLookups) - SPF allows maximum of 10";
        } elseif ($dnsLookups > 7) {
            $warnings[] = "High number of DNS lookups ($dnsLookups/10) - consider simplifying";
        }

        // Check for redirect
        if (isset($parsed['modifiers']['redirect'])) {
            $info[] = 'Record uses redirect to: ' . $parsed['modifiers']['redirect'];
        }

        // Check for ptr mechanism (deprecated)
        foreach ($parsed['mechanisms'] as $mech) {
            if ($mech['type'] === 'ptr') {
                $warnings[] = 'Using deprecated "ptr" mechanism - consider using "a" or "mx" instead';
                break;
            }
        }

        return [
            'errors' => $errors,
            'warnings' => $warnings,
            'info' => $info,
            'dns_lookups' => $dnsLookups,
        ];
    }

    /**
     * Count potential DNS lookups in SPF record
     */
    private function countDnsLookups(array $parsed): int
    {
        $count = 0;
        $lookupMechanisms = ['a', 'mx', 'ptr', 'exists', 'include'];

        foreach ($parsed['mechanisms'] as $mech) {
            if (in_array($mech['type'], $lookupMechanisms)) {
                $count++;
            }
        }

        // redirect counts as one lookup
        if (isset($parsed['modifiers']['redirect'])) {
            $count++;
        }

        return $count;
    }

    /**
     * Get recommendation based on SPF analysis
     */
    private function getRecommendation(array $parsed, array $issues): string
    {
        if (!empty($issues['errors'])) {
            return 'Fix the errors in your SPF record to ensure proper email authentication';
        }

        if (!empty($issues['warnings'])) {
            return 'Consider addressing the warnings to strengthen your SPF configuration';
        }

        if ($parsed['all'] === '-') {
            return 'SPF record is well configured with strict enforcement';
        }

        return 'SPF record is present and functional';
    }

    /**
     * Get a human-readable explanation of the qualifier
     */
    public function getQualifierMeaning(string $qualifier): string
    {
        return match ($qualifier) {
            '+' => 'Pass - Authorized sender',
            '-' => 'Fail - Not authorized',
            '~' => 'SoftFail - Probably not authorized',
            '?' => 'Neutral - No assertion',
            default => 'Unknown',
        };
    }
}
