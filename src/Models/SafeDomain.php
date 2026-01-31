<?php

declare(strict_types=1);

namespace Ephishchk\Models;

use Ephishchk\Core\Database;

/**
 * SafeDomain Model
 * Manages the list of trusted domains used for typosquatting detection
 */
class SafeDomain
{
    private Database $db;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Create a new safe domain entry with normalization
     */
    public function create(string $domain, int $userId, ?string $notes = null, ?string $username = null): ?int
    {
        $normalizedDomain = $this->normalizeDomain($domain);

        // Log normalization result to file AND error_log
        $debugLog = __DIR__ . "/../../storage/logs/safe_domain_debug.log";
        $timestamp = date('Y-m-d H:i:s');
        file_put_contents($debugLog, "[{$timestamp}] create() Input: '{$domain}' -> Normalized: '{$normalizedDomain}'\n", FILE_APPEND);

        error_log("[SafeDomain::create] Input: '{$domain}' -> Normalized: '{$normalizedDomain}'");

        // Prevent storing empty domains
        if (empty($normalizedDomain)) {
            file_put_contents($debugLog, "[{$timestamp}] ERROR: Normalized domain is empty, refusing to store\n", FILE_APPEND);
            error_log("[SafeDomain::create] ERROR: Normalized domain is empty, refusing to store");
            throw new \InvalidArgumentException("Invalid domain: '{$domain}' normalized to empty string");
        }

        // Check if domain already exists
        if ($this->exists($normalizedDomain)) {
            return null;
        }

        // If username not provided, fetch it from user_id
        if ($username === null) {
            $user = $this->db->fetchOne('SELECT username FROM users WHERE id = ?', [$userId]);
            error_log("[SafeDomain::create] User lookup for ID {$userId}: " . json_encode($user));
            $username = $user['username'] ?? 'System';
            error_log("[SafeDomain::create] Final username: {$username}");
        }

        return $this->db->insert('safe_domains', [
            'domain' => $normalizedDomain,
            'added_by_user_id' => $userId,
            'added_by_username' => $username,
            'notes' => $notes,
        ]);
    }

    /**
     * Get all safe domains with user information
     *
     * @param int|null $limit Maximum number of results to return
     * @param int $offset Number of results to skip
     * @return array
     */
    public function getAll(?int $limit = null, int $offset = 0): array
    {
        $sql = 'SELECT sd.*, sd.added_by_username, u.username
                FROM safe_domains sd
                LEFT JOIN users u ON sd.added_by_user_id = u.id
                ORDER BY sd.created_at DESC';

        if ($limit !== null) {
            $sql .= ' LIMIT ? OFFSET ?';
            return $this->db->fetchAll($sql, [$limit, $offset]);
        }

        return $this->db->fetchAll($sql);
    }

    /**
     * Get array of domain strings only (for typosquatting checks)
     */
    public function getAllDomainStrings(): array
    {
        $rows = $this->db->fetchAll('SELECT domain FROM safe_domains');
        return array_column($rows, 'domain');
    }

    /**
     * Check if a domain exists in the safe list
     */
    public function exists(string $domain): bool
    {
        $normalizedDomain = $this->normalizeDomain($domain);
        $result = $this->db->fetchOne(
            'SELECT id FROM safe_domains WHERE domain = ?',
            [$normalizedDomain]
        );
        return $result !== null;
    }

    /**
     * Delete a safe domain by ID
     */
    public function delete(int $id): bool
    {
        $this->db->query('DELETE FROM safe_domains WHERE id = ?', [$id]);
        return true;
    }

    /**
     * Find a safe domain by ID
     */
    public function find(int $id): ?array
    {
        return $this->db->fetchOne('SELECT * FROM safe_domains WHERE id = ?', [$id]);
    }

    /**
     * Normalize domain format for consistent storage and comparison
     * - Converts to lowercase
     * - Removes protocol (http://, https://)
     * - Removes www. prefix
     * - Removes trailing slashes and paths
     * - Extracts domain from URL if full URL provided
     */
    public function normalizeDomain(string $domain): string
    {
        $original = $domain;
        $debugLog = __DIR__ . "/../../storage/logs/safe_domain_debug.log";
        $timestamp = date('Y-m-d H:i:s');

        // Handle empty or null input
        if (empty($domain)) {
            file_put_contents($debugLog, "[{$timestamp}] normalizeDomain() Empty input\n", FILE_APPEND);
            error_log("[normalizeDomain] Empty input");
            return '';
        }

        // Trim whitespace
        $domain = trim($domain);
        file_put_contents($debugLog, "[{$timestamp}] After trim: '{$domain}'\n", FILE_APPEND);

        // Return empty if only whitespace
        if ($domain === '') {
            file_put_contents($debugLog, "[{$timestamp}] Only whitespace after trim\n", FILE_APPEND);
            return '';
        }

        // Convert to lowercase
        $domain = strtolower($domain);
        file_put_contents($debugLog, "[{$timestamp}] After lowercase: '{$domain}'\n", FILE_APPEND);

        // Remove protocol
        $result = preg_replace('#^https?://#i', '', $domain);
        if ($result === null) {
            file_put_contents($debugLog, "[{$timestamp}] Regex error on protocol removal\n", FILE_APPEND);
            return ''; // Regex error
        }
        $domain = $result;
        file_put_contents($debugLog, "[{$timestamp}] After protocol removal: '{$domain}'\n", FILE_APPEND);

        // Remove www. prefix
        $result = preg_replace('#^www\.#i', '', $domain);
        if ($result === null) {
            file_put_contents($debugLog, "[{$timestamp}] Regex error on www removal\n", FILE_APPEND);
            return ''; // Regex error
        }
        $domain = $result;
        file_put_contents($debugLog, "[{$timestamp}] After www removal: '{$domain}'\n", FILE_APPEND);

        // Remove path, query string, and fragment
        $result = preg_replace('#[/?\#].*$#', '', $domain);
        if ($result === null) {
            file_put_contents($debugLog, "[{$timestamp}] Regex error on path removal\n", FILE_APPEND);
            return ''; // Regex error
        }
        $domain = $result;
        file_put_contents($debugLog, "[{$timestamp}] After path removal: '{$domain}'\n", FILE_APPEND);

        // Remove port if present
        $result = preg_replace('#:\d+$#', '', $domain);
        if ($result === null) {
            file_put_contents($debugLog, "[{$timestamp}] Regex error on port removal\n", FILE_APPEND);
            return ''; // Regex error
        }
        $domain = $result;
        file_put_contents($debugLog, "[{$timestamp}] After port removal: '{$domain}'\n", FILE_APPEND);

        file_put_contents($debugLog, "[{$timestamp}] normalizeDomain() FINAL: '{$original}' -> '{$domain}'\n", FILE_APPEND);
        error_log("[normalizeDomain] FINAL: '{$original}' -> '{$domain}'");
        return $domain;
    }

    /**
     * Extract the second-level domain (SLD) from a domain
     * Example: 'login.google.com' -> 'google'
     * Example: 'google.com' -> 'google'
     */
    public function extractSLD(string $domain): string
    {
        $normalized = $this->normalizeDomain($domain);
        $parts = explode('.', $normalized);

        // Handle cases like 'google.co.uk' by taking second-to-last part
        if (count($parts) >= 2) {
            return $parts[count($parts) - 2];
        }

        return $normalized;
    }

    /**
     * Extract the base/root domain (SLD + TLD) from a domain with subdomains
     * Example: 'go.cloudplatformonline.com' -> 'cloudplatformonline.com'
     * Example: 'login.google.com' -> 'google.com'
     * Example: 'google.com' -> 'google.com'
     * Example: 'subdomain.example.co.uk' -> 'example.co.uk'
     */
    public function extractBaseDomain(string $domain): string
    {
        $normalized = $this->normalizeDomain($domain);
        $parts = explode('.', $normalized);

        // List of known two-part TLDs (not comprehensive, but covers common cases)
        $twoPartTlds = ['co.uk', 'com.au', 'co.nz', 'co.za', 'com.br', 'co.jp'];

        // If only 2 parts (e.g., 'google.com'), return as-is
        if (count($parts) <= 2) {
            return $normalized;
        }

        // Check if it uses a two-part TLD
        $lastTwoParts = $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];
        if (in_array($lastTwoParts, $twoPartTlds)) {
            // Take last 3 parts (subdomain.example.co.uk -> example.co.uk)
            if (count($parts) >= 3) {
                return $parts[count($parts) - 3] . '.' . $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];
            }
        }

        // Default: take last 2 parts (go.cloudplatformonline.com -> cloudplatformonline.com)
        return $parts[count($parts) - 2] . '.' . $parts[count($parts) - 1];
    }

    /**
     * Count total safe domains
     */
    public function count(): int
    {
        return (int) $this->db->fetchColumn('SELECT COUNT(*) FROM safe_domains');
    }
}
