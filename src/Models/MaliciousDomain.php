<?php

declare(strict_types=1);

namespace Ephishchk\Models;

use Ephishchk\Core\Database;

/**
 * MaliciousDomain Model
 * Manages the list of known malicious domains used for confirmed phish detection
 */
class MaliciousDomain
{
    private Database $db;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Create a new malicious domain entry with normalization
     */
    public function create(string $domain, int $userId, ?string $notes = null, ?string $username = null): ?int
    {
        $normalizedDomain = $this->normalizeDomain($domain);

        if (empty($normalizedDomain)) {
            throw new \InvalidArgumentException("Invalid domain: '{$domain}' normalized to empty string");
        }

        // Check if domain already exists
        if ($this->exists($normalizedDomain)) {
            return null;
        }

        // If username not provided, fetch it from user_id
        if ($username === null) {
            $user = $this->db->fetchOne('SELECT username FROM users WHERE id = ?', [$userId]);
            $username = $user['username'] ?? 'System';
        }

        return $this->db->insert('malicious_domains', [
            'domain' => $normalizedDomain,
            'added_by_user_id' => $userId,
            'added_by_username' => $username,
            'notes' => $notes,
        ]);
    }

    /**
     * Get all malicious domains with user information
     */
    public function getAll(?int $limit = null, int $offset = 0): array
    {
        $sql = 'SELECT md.*, md.added_by_username, u.username
                FROM malicious_domains md
                LEFT JOIN users u ON md.added_by_user_id = u.id
                ORDER BY md.created_at DESC';

        if ($limit !== null) {
            $sql .= ' LIMIT ? OFFSET ?';
            return $this->db->fetchAll($sql, [$limit, $offset]);
        }

        return $this->db->fetchAll($sql);
    }

    /**
     * Get array of domain strings only (for malicious domain checks)
     */
    public function getAllDomainStrings(): array
    {
        $rows = $this->db->fetchAll('SELECT domain FROM malicious_domains');
        return array_column($rows, 'domain');
    }

    /**
     * Check if a domain exists in the malicious list
     */
    public function exists(string $domain): bool
    {
        $normalizedDomain = $this->normalizeDomain($domain);
        $result = $this->db->fetchOne(
            'SELECT id FROM malicious_domains WHERE domain = ?',
            [$normalizedDomain]
        );
        return $result !== null;
    }

    /**
     * Delete a malicious domain by ID
     */
    public function delete(int $id): bool
    {
        $this->db->query('DELETE FROM malicious_domains WHERE id = ?', [$id]);
        return true;
    }

    /**
     * Find a malicious domain by ID
     */
    public function find(int $id): ?array
    {
        return $this->db->fetchOne('SELECT * FROM malicious_domains WHERE id = ?', [$id]);
    }

    /**
     * Normalize domain format for consistent storage and comparison
     */
    public function normalizeDomain(string $domain): string
    {
        if (empty($domain)) {
            return '';
        }

        $domain = trim($domain);

        if ($domain === '') {
            return '';
        }

        // Convert to lowercase
        $domain = strtolower($domain);

        // Remove protocol
        $result = preg_replace('#^https?://#i', '', $domain);
        if ($result === null) {
            return '';
        }
        $domain = $result;

        // Remove www. prefix
        $result = preg_replace('#^www\.#i', '', $domain);
        if ($result === null) {
            return '';
        }
        $domain = $result;

        // Remove path, query string, and fragment
        $result = preg_replace('#[/?\#].*$#', '', $domain);
        if ($result === null) {
            return '';
        }
        $domain = $result;

        // Remove port if present
        $result = preg_replace('#:\d+$#', '', $domain);
        if ($result === null) {
            return '';
        }
        $domain = $result;

        return $domain;
    }

    /**
     * Count total malicious domains
     */
    public function count(): int
    {
        return (int) $this->db->fetchColumn('SELECT COUNT(*) FROM malicious_domains');
    }
}
