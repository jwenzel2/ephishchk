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
    public function create(string $domain, int $userId, ?string $notes = null): ?int
    {
        $normalizedDomain = $this->normalizeDomain($domain);

        // Log normalization result
        error_log("[SafeDomain::create] Input: '{$domain}' -> Normalized: '{$normalizedDomain}'");

        // Prevent storing empty domains
        if (empty($normalizedDomain)) {
            error_log("[SafeDomain::create] ERROR: Normalized domain is empty, refusing to store");
            throw new \InvalidArgumentException("Invalid domain: '{$domain}' normalized to empty string");
        }

        // Check if domain already exists
        if ($this->exists($normalizedDomain)) {
            return null;
        }

        return $this->db->insert('safe_domains', [
            'domain' => $normalizedDomain,
            'added_by_user_id' => $userId,
            'notes' => $notes,
        ]);
    }

    /**
     * Get all safe domains with user information
     */
    public function getAll(): array
    {
        return $this->db->fetchAll(
            'SELECT sd.*, u.email as added_by_email
             FROM safe_domains sd
             LEFT JOIN users u ON sd.added_by_user_id = u.id
             ORDER BY sd.created_at DESC'
        );
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

        // Handle empty or null input
        if (empty($domain)) {
            error_log("[normalizeDomain] Empty input");
            return '';
        }

        // Trim whitespace
        $domain = trim($domain);
        error_log("[normalizeDomain] After trim: '{$domain}'");

        // Return empty if only whitespace
        if ($domain === '') {
            error_log("[normalizeDomain] Only whitespace after trim");
            return '';
        }

        // Convert to lowercase
        $domain = strtolower($domain);
        error_log("[normalizeDomain] After lowercase: '{$domain}'");

        // Remove protocol
        $result = preg_replace('#^https?://#i', '', $domain);
        if ($result === null) {
            error_log("[normalizeDomain] Regex error on protocol removal");
            return ''; // Regex error
        }
        $domain = $result;
        error_log("[normalizeDomain] After protocol removal: '{$domain}'");

        // Remove www. prefix
        $result = preg_replace('#^www\.#i', '', $domain);
        if ($result === null) {
            error_log("[normalizeDomain] Regex error on www removal");
            return ''; // Regex error
        }
        $domain = $result;
        error_log("[normalizeDomain] After www removal: '{$domain}'");

        // Remove path, query string, and fragment
        $result = preg_replace('#[/?#].*$#', '', $domain);
        if ($result === null) {
            error_log("[normalizeDomain] Regex error on path removal");
            return ''; // Regex error
        }
        $domain = $result;
        error_log("[normalizeDomain] After path removal: '{$domain}'");

        // Remove port if present
        $result = preg_replace('#:\d+$#', '', $domain);
        if ($result === null) {
            error_log("[normalizeDomain] Regex error on port removal");
            return ''; // Regex error
        }
        $domain = $result;
        error_log("[normalizeDomain] After port removal: '{$domain}'");

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
     * Count total safe domains
     */
    public function count(): int
    {
        return (int) $this->db->fetchColumn('SELECT COUNT(*) FROM safe_domains');
    }
}
