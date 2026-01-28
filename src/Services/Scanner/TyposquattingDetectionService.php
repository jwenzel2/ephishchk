<?php

declare(strict_types=1);

namespace Ephishchk\Services\Scanner;

/**
 * Typosquatting Detection Service - detects typosquatting attempts against safe domains
 *
 * Uses multiple detection techniques:
 * 1. Levenshtein distance - detects 1-2 character differences
 * 2. Character substitution - detects l33t speak variants (g00gle, paypa1)
 * 3. Homograph attacks - detects punycode/visually similar characters
 */
class TyposquattingDetectionService
{
    /**
     * Check a domain against a list of safe domains for typosquatting attempts
     *
     * @param string $domain The domain to check
     * @param array $safeDomains Array of safe domain strings
     * @return array|null Finding array if typosquatting detected, null otherwise
     */
    public function checkDomainAgainstSafeList(string $domain, array $safeDomains): ?array
    {
        // Debug logging
        error_log("[TyposquattingDetection] Checking domain: $domain");
        error_log("[TyposquattingDetection] Safe domains count: " . count($safeDomains));
        error_log("[TyposquattingDetection] Safe domains: " . implode(', ', array_slice($safeDomains, 0, 10)));

        // Normalize the scanned domain
        $normalizedDomain = strtolower($domain);
        $normalizedDomain = preg_replace('/^www\./', '', $normalizedDomain);

        // Extract second-level domain (SLD) for comparison
        $scannedSLD = $this->extractSecondLevelDomain($normalizedDomain);
        error_log("[TyposquattingDetection] Scanned SLD: $scannedSLD");

        foreach ($safeDomains as $safeDomain) {
            $normalizedSafe = strtolower($safeDomain);
            $normalizedSafe = preg_replace('/^www\./', '', $normalizedSafe);

            // Extract SLD from safe domain
            $safeSLD = $this->extractSecondLevelDomain($normalizedSafe);

            // Skip exact matches
            if ($scannedSLD === $safeSLD || $normalizedDomain === $normalizedSafe) {
                continue;
            }

            // Allow legitimate subdomains of safe domains
            if (str_ends_with($normalizedDomain, '.' . $normalizedSafe)) {
                continue;
            }

            // Skip very short domains to avoid false positives
            if (strlen($safeSLD) <= 5) {
                error_log("[TyposquattingDetection] Skipping $safeSLD (too short: " . strlen($safeSLD) . " chars)");
                continue;
            }

            // 1. Check Levenshtein distance (1-2 character difference)
            $distance = levenshtein($scannedSLD, $safeSLD);
            error_log("[TyposquattingDetection] Comparing '$scannedSLD' vs '$safeSLD' - distance: $distance");
            if ($distance > 0 && $distance <= 2) {
                error_log("[TyposquattingDetection] ✓ MATCH FOUND! Typosquatting detected");
                return [
                    'type' => 'typosquatting_safe_domain',
                    'severity' => 'high',
                    'scanned_domain' => $domain,
                    'matched_safe_domain' => $safeDomain,
                    'message' => "Possible typosquatting of trusted domain: {$safeDomain}",
                    'details' => "Domain uses character differences (Levenshtein distance: {$distance})",
                ];
            }

            // 2. Check character substitution (l33t speak)
            if ($this->isCharacterSubstitution($scannedSLD, $safeSLD)) {
                return [
                    'type' => 'typosquatting_safe_domain',
                    'severity' => 'high',
                    'scanned_domain' => $domain,
                    'matched_safe_domain' => $safeDomain,
                    'message' => "Possible typosquatting of trusted domain: {$safeDomain}",
                    'details' => "Domain uses character substitution (0→o, 1→l, etc.)",
                ];
            }

            // 3. Check for homograph attacks (punycode)
            if (str_contains($normalizedDomain, 'xn--')) {
                // Check if decoded domain is similar to safe domain
                $decoded = idn_to_utf8($normalizedDomain);
                if ($decoded && str_contains(strtolower($decoded), $safeSLD)) {
                    return [
                        'type' => 'typosquatting_safe_domain',
                        'severity' => 'high',
                        'scanned_domain' => $domain,
                        'matched_safe_domain' => $safeDomain,
                        'message' => "Possible homograph attack targeting trusted domain: {$safeDomain}",
                        'details' => "Domain uses punycode encoding to visually mimic the trusted domain",
                    ];
                }
            }
        }

        error_log("[TyposquattingDetection] No typosquatting detected for domain: $domain");
        return null;
    }

    /**
     * Extract second-level domain (SLD) from a full domain
     * Example: 'login.google.com' -> 'google'
     * Example: 'google.com' -> 'google'
     *
     * @param string $domain The domain to extract from
     * @return string The second-level domain
     */
    public function extractSecondLevelDomain(string $domain): string
    {
        $parts = explode('.', $domain);

        // Handle cases like 'google.co.uk' by taking second-to-last part
        if (count($parts) >= 2) {
            return $parts[count($parts) - 2];
        }

        return $domain;
    }

    /**
     * Check if scanned domain uses character substitution to mimic safe domain
     * Detects: 0→o, 1→l, 3→e, 4→a, 5→s, 7→t, @→a, $→s
     *
     * @param string $scanned The scanned (potentially malicious) domain
     * @param string $safe The safe domain to compare against
     * @return bool True if character substitution detected
     */
    private function isCharacterSubstitution(string $scanned, string $safe): bool
    {
        $substitutions = [
            '0' => 'o',
            '1' => ['l', 'i'],
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '@' => 'a',
            '$' => 's',
        ];

        // Create all possible substitution variants of the safe domain
        $variants = [$safe];

        foreach ($substitutions as $leetChar => $normalChars) {
            $normalChars = is_array($normalChars) ? $normalChars : [$normalChars];
            $newVariants = [];

            foreach ($variants as $variant) {
                foreach ($normalChars as $normalChar) {
                    if (str_contains($variant, $normalChar)) {
                        $newVariants[] = str_replace($normalChar, $leetChar, $variant);
                    }
                }
            }

            $variants = array_merge($variants, $newVariants);
        }

        return in_array($scanned, $variants);
    }
}
