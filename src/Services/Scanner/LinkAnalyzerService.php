<?php

declare(strict_types=1);

namespace Ephishchk\Services\Scanner;

use Ephishchk\Services\Authentication\DnsLookupService;

/**
 * Link Analyzer Service - analyzes URLs for suspicious patterns
 */
class LinkAnalyzerService
{
    private DnsLookupService $dns;

    // Known URL shortener domains
    private const URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'rebrand.ly', 'cutt.ly',
        'short.io', 'tiny.cc', 'rb.gy', 'shorturl.at', 'v.gd',
    ];

    // Suspicious TLDs often used in phishing
    private const SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', // Free TLDs
        'xyz', 'top', 'club', 'online', 'site', 'icu',
        'buzz', 'cam', 'monster', 'loan', 'work',
    ];

    // Commonly impersonated brands
    private const COMMON_BRANDS = [
        'paypal', 'amazon', 'microsoft', 'apple', 'google',
        'facebook', 'netflix', 'bank', 'chase', 'wellsfargo',
        'citibank', 'hsbc', 'dropbox', 'linkedin', 'instagram',
        'twitter', 'outlook', 'office365', 'icloud', 'steam',
    ];

    public function __construct(DnsLookupService $dns)
    {
        $this->dns = $dns;
    }

    /**
     * Analyze a URL for suspicious indicators
     *
     * @return array{url: string, domain: string, score: int, findings: array}
     */
    public function analyze(string $url): array
    {
        $findings = [];
        $score = 0;

        $parsed = parse_url($url);
        $domain = strtolower($parsed['host'] ?? '');
        $path = $parsed['path'] ?? '/';

        // Check if domain exists
        if (!$this->dns->domainExists($domain)) {
            $findings[] = [
                'type' => 'domain_not_found',
                'severity' => 'high',
                'message' => 'Domain does not exist or has no DNS records',
            ];
            $score += 40;
        }

        // Check for IP address instead of domain
        if (filter_var($domain, FILTER_VALIDATE_IP)) {
            $findings[] = [
                'type' => 'ip_address',
                'severity' => 'high',
                'message' => 'URL uses IP address instead of domain name',
                'details' => 'Legitimate websites typically use domain names',
            ];
            $score += 30;
        }

        // Check for URL shortener
        if ($this->isUrlShortener($domain)) {
            $findings[] = [
                'type' => 'url_shortener',
                'severity' => 'warning',
                'message' => 'URL uses a URL shortening service',
                'details' => 'Shortened URLs can hide the actual destination',
            ];
            $score += 15;
        }

        // Check TLD
        $tld = $this->extractTld($domain);
        if (in_array($tld, self::SUSPICIOUS_TLDS)) {
            $findings[] = [
                'type' => 'suspicious_tld',
                'severity' => 'warning',
                'message' => "Uses suspicious TLD: .$tld",
                'details' => 'This TLD is commonly used in phishing attacks',
            ];
            $score += 15;
        }

        // Check for brand impersonation
        $brandCheck = $this->checkBrandImpersonation($domain);
        if ($brandCheck) {
            $findings[] = $brandCheck;
            $score += 25;
        }

        // Check for excessive subdomains
        $subdomainCount = substr_count($domain, '.') - 1;
        if ($subdomainCount > 3) {
            $findings[] = [
                'type' => 'excessive_subdomains',
                'severity' => 'warning',
                'message' => "Domain has $subdomainCount subdomains",
                'details' => 'Excessive subdomains can be used to deceive users',
            ];
            $score += 10;
        }

        // Check for suspicious characters in domain
        if ($this->hasSuspiciousCharacters($domain)) {
            $findings[] = [
                'type' => 'suspicious_characters',
                'severity' => 'warning',
                'message' => 'Domain contains suspicious characters or patterns',
                'details' => 'May be attempting to impersonate another domain',
            ];
            $score += 20;
        }

        // Check path for suspicious patterns
        $pathFindings = $this->analyzePath($path);
        foreach ($pathFindings as $finding) {
            $findings[] = $finding;
            $score += $finding['severity'] === 'high' ? 15 : 10;
        }

        // Check for HTTPS
        if (($parsed['scheme'] ?? 'http') !== 'https') {
            $findings[] = [
                'type' => 'no_https',
                'severity' => 'info',
                'message' => 'URL does not use HTTPS',
                'details' => 'Data sent to this URL is not encrypted',
            ];
            $score += 5;
        }

        // Normalize score
        $score = min(100, $score);

        return [
            'url' => $url,
            'domain' => $domain,
            'score' => $score,
            'findings' => $findings,
            'risk_level' => $this->getRiskLevel($score),
        ];
    }

    /**
     * Analyze multiple URLs
     */
    public function analyzeMultiple(array $urls): array
    {
        $results = [];

        foreach ($urls as $urlData) {
            $url = is_array($urlData) ? $urlData['url'] : $urlData;
            $result = $this->analyze($url);

            if (is_array($urlData) && isset($urlData['text'])) {
                $result['link_text'] = $urlData['text'];
            }

            $results[] = $result;
        }

        return $results;
    }

    /**
     * Check if domain is a URL shortener
     */
    private function isUrlShortener(string $domain): bool
    {
        foreach (self::URL_SHORTENERS as $shortener) {
            if ($domain === $shortener || str_ends_with($domain, '.' . $shortener)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract TLD from domain
     */
    private function extractTld(string $domain): string
    {
        $parts = explode('.', $domain);
        return end($parts);
    }

    /**
     * Check for potential brand impersonation
     */
    private function checkBrandImpersonation(string $domain): ?array
    {
        // Remove common TLDs for checking
        $domainWithoutTld = preg_replace('/\.[a-z]{2,}$/i', '', $domain);
        $domainParts = explode('.', $domainWithoutTld);

        foreach (self::COMMON_BRANDS as $brand) {
            // Check if brand name appears in domain but isn't the actual brand domain
            if (str_contains($domain, $brand)) {
                $legitDomains = $this->getLegitDomainsForBrand($brand);
                $isLegit = false;

                foreach ($legitDomains as $legitDomain) {
                    if ($domain === $legitDomain || str_ends_with($domain, '.' . $legitDomain)) {
                        $isLegit = true;
                        break;
                    }
                }

                if (!$isLegit) {
                    return [
                        'type' => 'brand_impersonation',
                        'severity' => 'high',
                        'message' => "Possible impersonation of $brand",
                        'details' => "Domain contains '$brand' but doesn't appear to be official",
                    ];
                }
            }

            // Check for typosquatting (common character substitutions)
            $typoVariants = $this->getTypoVariants($brand);
            foreach ($typoVariants as $variant) {
                if (str_contains($domainWithoutTld, $variant)) {
                    return [
                        'type' => 'typosquatting',
                        'severity' => 'high',
                        'message' => "Possible typosquatting attempt targeting $brand",
                        'details' => "Domain contains '$variant' which resembles '$brand'",
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Get legitimate domains for a brand
     */
    private function getLegitDomainsForBrand(string $brand): array
    {
        $domains = [
            'paypal' => ['paypal.com', 'paypal.me'],
            'amazon' => ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'aws.amazon.com'],
            'microsoft' => ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
            'apple' => ['apple.com', 'icloud.com'],
            'google' => ['google.com', 'gmail.com', 'youtube.com'],
            'facebook' => ['facebook.com', 'fb.com', 'meta.com'],
            'netflix' => ['netflix.com'],
            'bank' => [], // Generic term
            'chase' => ['chase.com'],
            'wellsfargo' => ['wellsfargo.com'],
            'citibank' => ['citibank.com', 'citi.com'],
            'hsbc' => ['hsbc.com'],
            'dropbox' => ['dropbox.com'],
            'linkedin' => ['linkedin.com'],
            'instagram' => ['instagram.com'],
            'twitter' => ['twitter.com', 'x.com'],
            'outlook' => ['outlook.com'],
            'office365' => ['office365.com', 'office.com'],
            'icloud' => ['icloud.com'],
            'steam' => ['steampowered.com', 'steamcommunity.com'],
        ];

        return $domains[$brand] ?? [];
    }

    /**
     * Generate common typosquatting variants
     */
    private function getTypoVariants(string $brand): array
    {
        $variants = [];

        // Character substitutions
        $substitutions = [
            'a' => ['4', '@'],
            'e' => ['3'],
            'i' => ['1', 'l', '!'],
            'l' => ['1', 'i'],
            'o' => ['0'],
            's' => ['5', '$'],
            't' => ['7'],
        ];

        foreach ($substitutions as $char => $replacements) {
            if (str_contains($brand, $char)) {
                foreach ($replacements as $replacement) {
                    $variants[] = str_replace($char, $replacement, $brand);
                }
            }
        }

        // Common double character typos
        for ($i = 0; $i < strlen($brand) - 1; $i++) {
            $char = $brand[$i];
            // Double a character
            $variants[] = substr($brand, 0, $i + 1) . $char . substr($brand, $i + 1);
        }

        return $variants;
    }

    /**
     * Check for suspicious characters in domain
     */
    private function hasSuspiciousCharacters(string $domain): bool
    {
        // Check for punycode (internationalized domain names)
        if (str_contains($domain, 'xn--')) {
            return true;
        }

        // Check for unusual character patterns
        if (preg_match('/[0-9]{4,}/', $domain)) {
            return true; // Long number sequences
        }

        if (preg_match('/[-]{2,}/', $domain)) {
            return true; // Multiple consecutive hyphens
        }

        return false;
    }

    /**
     * Analyze URL path for suspicious patterns
     */
    private function analyzePath(string $path): array
    {
        $findings = [];

        // Check for suspicious file extensions
        if (preg_match('/\.(exe|bat|cmd|scr|js|vbs|ps1|php)$/i', $path)) {
            $findings[] = [
                'type' => 'suspicious_extension',
                'severity' => 'high',
                'message' => 'URL points to potentially dangerous file type',
            ];
        }

        // Check for encoded characters (possible obfuscation)
        if (preg_match('/%[0-9a-f]{2}/i', $path)) {
            $decodedPath = urldecode($path);
            if ($decodedPath !== $path && preg_match('/[<>"\']/', $decodedPath)) {
                $findings[] = [
                    'type' => 'encoded_suspicious_chars',
                    'severity' => 'warning',
                    'message' => 'URL path contains encoded suspicious characters',
                ];
            }
        }

        // Check for data exfiltration patterns
        if (preg_match('/password|login|signin|account|verify|update|confirm/i', $path)) {
            $findings[] = [
                'type' => 'phishing_keywords',
                'severity' => 'warning',
                'message' => 'URL path contains common phishing keywords',
            ];
        }

        return $findings;
    }

    /**
     * Get risk level label from score
     */
    private function getRiskLevel(int $score): string
    {
        if ($score >= 50) {
            return 'high';
        }
        if ($score >= 25) {
            return 'medium';
        }
        return 'low';
    }
}
