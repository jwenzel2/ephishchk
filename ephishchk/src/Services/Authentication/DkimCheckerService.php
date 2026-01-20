<?php

declare(strict_types=1);

namespace Ephishchk\Services\Authentication;

/**
 * DKIM Record Checker Service
 */
class DkimCheckerService
{
    private DnsLookupService $dns;
    private array $selectors;

    public function __construct(DnsLookupService $dns, array $selectors = [])
    {
        $this->dns = $dns;
        $this->selectors = $selectors ?: [
            'default',
            'google',
            'selector1',
            'selector2',
            's1',
            's2',
            'k1',
            'k2',
            'mail',
            'email',
            'dkim',
            'smtp',
        ];
    }

    /**
     * Check DKIM records for a domain by scanning common selectors
     *
     * @return array{status: string, selectors: array, details: array}
     */
    public function check(string $domain): array
    {
        $foundSelectors = [];
        $checkedSelectors = [];

        foreach ($this->selectors as $selector) {
            $record = $this->dns->getDkimRecord($domain, $selector);
            $checkedSelectors[] = $selector;

            if ($record !== null) {
                $parsed = $this->parseDkimRecord($record);
                $validation = $this->validateDkim($parsed);

                $foundSelectors[$selector] = [
                    'record' => $record,
                    'parsed' => $parsed,
                    'validation' => $validation,
                ];
            }
        }

        if (empty($foundSelectors)) {
            return [
                'status' => 'warning',
                'selectors' => [],
                'details' => [
                    'message' => 'No DKIM records found for common selectors',
                    'checked_selectors' => $checkedSelectors,
                    'note' => 'DKIM selectors are domain-specific. The actual selector may not be in our list.',
                    'recommendation' => 'Check email headers for the exact DKIM selector used',
                ],
            ];
        }

        // Determine overall status
        $hasErrors = false;
        $hasWarnings = false;

        foreach ($foundSelectors as $data) {
            if (!empty($data['validation']['errors'])) {
                $hasErrors = true;
            }
            if (!empty($data['validation']['warnings'])) {
                $hasWarnings = true;
            }
        }

        $status = 'pass';
        if ($hasErrors) {
            $status = 'fail';
        } elseif ($hasWarnings) {
            $status = 'warning';
        }

        return [
            'status' => $status,
            'selectors' => $foundSelectors,
            'details' => [
                'found_count' => count($foundSelectors),
                'checked_selectors' => $checkedSelectors,
                'recommendation' => $this->getRecommendation($foundSelectors),
            ],
        ];
    }

    /**
     * Check a specific DKIM selector
     *
     * @return array{status: string, record: ?string, parsed: ?array, validation: ?array}
     */
    public function checkSelector(string $domain, string $selector): array
    {
        $record = $this->dns->getDkimRecord($domain, $selector);

        if ($record === null) {
            return [
                'status' => 'fail',
                'record' => null,
                'parsed' => null,
                'validation' => [
                    'errors' => ["No DKIM record found for selector: $selector"],
                ],
            ];
        }

        $parsed = $this->parseDkimRecord($record);
        $validation = $this->validateDkim($parsed);

        $status = 'pass';
        if (!empty($validation['errors'])) {
            $status = 'fail';
        } elseif (!empty($validation['warnings'])) {
            $status = 'warning';
        }

        return [
            'status' => $status,
            'record' => $record,
            'parsed' => $parsed,
            'validation' => $validation,
        ];
    }

    /**
     * Parse DKIM record into components
     */
    public function parseDkimRecord(string $record): array
    {
        $parsed = [
            'version' => null,
            'key_type' => 'rsa', // Default
            'public_key' => null,
            'hash_algorithms' => null,
            'service_type' => null,
            'flags' => null,
            'notes' => null,
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
            $tag = trim($tag);
            $value = trim($value);

            switch ($tag) {
                case 'v':
                    $parsed['version'] = $value;
                    break;
                case 'k':
                    $parsed['key_type'] = $value;
                    break;
                case 'p':
                    $parsed['public_key'] = $value;
                    break;
                case 'h':
                    $parsed['hash_algorithms'] = $value;
                    break;
                case 's':
                    $parsed['service_type'] = $value;
                    break;
                case 't':
                    $parsed['flags'] = $value;
                    break;
                case 'n':
                    $parsed['notes'] = $value;
                    break;
            }
        }

        return $parsed;
    }

    /**
     * Validate DKIM record
     */
    private function validateDkim(array $parsed): array
    {
        $errors = [];
        $warnings = [];
        $info = [];

        // Check public key
        if (empty($parsed['public_key'])) {
            $errors[] = 'No public key found (p= tag is empty or missing)';
        } elseif ($parsed['public_key'] === '') {
            $info[] = 'DKIM key has been revoked (empty p= value)';
        } else {
            // Check key length (rough estimate from base64)
            $keyLength = strlen($parsed['public_key']) * 6 / 8;
            if ($keyLength < 128) {
                $errors[] = 'Public key appears too short - may be invalid';
            } elseif ($keyLength < 256) {
                $warnings[] = 'Public key may be weak - consider using a longer key';
            }
        }

        // Check key type
        if ($parsed['key_type'] !== null && $parsed['key_type'] !== 'rsa' && $parsed['key_type'] !== 'ed25519') {
            $warnings[] = 'Unusual key type: ' . $parsed['key_type'];
        }

        if ($parsed['key_type'] === 'ed25519') {
            $info[] = 'Using Ed25519 algorithm (modern, efficient)';
        }

        // Check for testing flag
        if ($parsed['flags'] !== null && str_contains($parsed['flags'], 'y')) {
            $warnings[] = 'DKIM record is in testing mode (t=y)';
        }

        // Check service type restriction
        if ($parsed['service_type'] !== null && $parsed['service_type'] !== '*') {
            $info[] = 'Service type restricted to: ' . $parsed['service_type'];
        }

        return [
            'errors' => $errors,
            'warnings' => $warnings,
            'info' => $info,
        ];
    }

    /**
     * Get recommendation based on DKIM analysis
     */
    private function getRecommendation(array $foundSelectors): string
    {
        if (empty($foundSelectors)) {
            return 'Configure DKIM signing for your domain to improve email deliverability';
        }

        $hasErrors = false;
        foreach ($foundSelectors as $data) {
            if (!empty($data['validation']['errors'])) {
                $hasErrors = true;
                break;
            }
        }

        if ($hasErrors) {
            return 'Fix the DKIM record errors to ensure proper email authentication';
        }

        return 'DKIM is configured and functional';
    }
}
