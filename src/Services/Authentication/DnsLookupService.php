<?php

declare(strict_types=1);

namespace Ephishchk\Services\Authentication;

/**
 * DNS Lookup Service with caching
 */
class DnsLookupService
{
    private array $cache = [];
    private int $cacheTtl;

    public function __construct(int $cacheTtl = 300)
    {
        $this->cacheTtl = $cacheTtl;
    }

    /**
     * Get TXT records for a domain
     */
    public function getTxtRecords(string $domain): array
    {
        return $this->lookup($domain, DNS_TXT);
    }

    /**
     * Get MX records for a domain
     */
    public function getMxRecords(string $domain): array
    {
        return $this->lookup($domain, DNS_MX);
    }

    /**
     * Get A records for a domain
     */
    public function getARecords(string $domain): array
    {
        return $this->lookup($domain, DNS_A);
    }

    /**
     * Get AAAA (IPv6) records for a domain
     */
    public function getAaaaRecords(string $domain): array
    {
        return $this->lookup($domain, DNS_AAAA);
    }

    /**
     * Get specific TXT records matching a prefix (e.g., "v=spf1")
     */
    public function getTxtRecordsByPrefix(string $domain, string $prefix): array
    {
        $records = $this->getTxtRecords($domain);
        $matching = [];

        foreach ($records as $record) {
            if (isset($record['txt']) && str_starts_with($record['txt'], $prefix)) {
                $matching[] = $record['txt'];
            }
        }

        return $matching;
    }

    /**
     * Check if a domain has any DNS records
     */
    public function domainExists(string $domain): bool
    {
        $records = $this->lookup($domain, DNS_ANY);
        return !empty($records);
    }

    /**
     * Get SPF record for a domain
     */
    public function getSpfRecord(string $domain): ?string
    {
        $records = $this->getTxtRecordsByPrefix($domain, 'v=spf1');
        return $records[0] ?? null;
    }

    /**
     * Get DMARC record for a domain
     */
    public function getDmarcRecord(string $domain): ?string
    {
        $dmarcDomain = '_dmarc.' . $domain;
        $records = $this->getTxtRecordsByPrefix($dmarcDomain, 'v=DMARC1');
        return $records[0] ?? null;
    }

    /**
     * Get DKIM record for a domain and selector
     */
    public function getDkimRecord(string $domain, string $selector): ?string
    {
        $dkimDomain = $selector . '._domainkey.' . $domain;
        $records = $this->getTxtRecordsByPrefix($dkimDomain, 'v=DKIM1');

        if (!empty($records)) {
            return $records[0];
        }

        // Some DKIM records don't start with v=DKIM1
        $allRecords = $this->getTxtRecords($dkimDomain);
        foreach ($allRecords as $record) {
            if (isset($record['txt']) && (str_contains($record['txt'], 'p=') || str_contains($record['txt'], 'k='))) {
                return $record['txt'];
            }
        }

        return null;
    }

    /**
     * Resolve hostname to IP addresses
     */
    public function resolveHost(string $hostname): array
    {
        $ips = [];

        // Get IPv4 addresses
        $aRecords = $this->getARecords($hostname);
        foreach ($aRecords as $record) {
            if (isset($record['ip'])) {
                $ips[] = $record['ip'];
            }
        }

        // Get IPv6 addresses
        $aaaaRecords = $this->getAaaaRecords($hostname);
        foreach ($aaaaRecords as $record) {
            if (isset($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }

        return $ips;
    }

    /**
     * Perform DNS lookup with caching
     */
    private function lookup(string $domain, int $type): array
    {
        $cacheKey = $domain . '_' . $type;

        // Check cache
        if (isset($this->cache[$cacheKey])) {
            $cached = $this->cache[$cacheKey];
            if ($cached['expires'] > time()) {
                return $cached['data'];
            }
            unset($this->cache[$cacheKey]);
        }

        // Perform lookup
        $records = @dns_get_record($domain, $type);

        if ($records === false) {
            $records = [];
        }

        // Cache result
        $this->cache[$cacheKey] = [
            'data' => $records,
            'expires' => time() + $this->cacheTtl,
        ];

        return $records;
    }

    /**
     * Clear the cache
     */
    public function clearCache(): void
    {
        $this->cache = [];
    }

    /**
     * Get the reverse DNS hostname for an IP
     */
    public function getReverseDns(string $ip): ?string
    {
        $hostname = @gethostbyaddr($ip);
        return ($hostname !== $ip) ? $hostname : null;
    }
}
