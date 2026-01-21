<?php

declare(strict_types=1);

namespace Ephishchk\Models;

use Ephishchk\Core\Database;

/**
 * Scan Model
 */
class Scan
{
    private Database $db;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Create a new scan
     */
    public function create(array $data): int
    {
        $insertData = [
            'scan_type' => $data['scan_type'],
            'input_identifier' => $data['input_identifier'],
            'input_hash' => hash('sha256', $data['input_identifier']),
            'status' => 'pending',
            'ip_address' => $data['ip_address'] ?? '127.0.0.1',
        ];

        if (isset($data['user_id'])) {
            $insertData['user_id'] = $data['user_id'];
        }

        return $this->db->insert('scans', $insertData);
    }

    /**
     * Find scan by ID
     */
    public function find(int $id): ?array
    {
        return $this->db->fetchOne('SELECT * FROM scans WHERE id = ?', [$id]);
    }

    /**
     * Update scan status
     */
    public function updateStatus(int $id, string $status, ?int $riskScore = null): void
    {
        $data = ['status' => $status];

        if ($riskScore !== null) {
            $data['risk_score'] = $riskScore;
        }

        if ($status === 'completed' || $status === 'failed') {
            $this->db->query(
                'UPDATE scans SET status = ?, risk_score = ?, completed_at = NOW() WHERE id = ?',
                [$status, $riskScore, $id]
            );
        } else {
            $this->db->update('scans', $data, 'id = ?', [$id]);
        }
    }

    /**
     * Get recent scans for history
     */
    public function getRecent(int $limit = 50, int $offset = 0): array
    {
        return $this->db->fetchAll(
            'SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?',
            [$limit, $offset]
        );
    }

    /**
     * Get scans by IP address
     */
    public function getByIpAddress(string $ipAddress, int $limit = 10): array
    {
        return $this->db->fetchAll(
            'SELECT * FROM scans WHERE ip_address = ? ORDER BY created_at DESC LIMIT ?',
            [$ipAddress, $limit]
        );
    }

    /**
     * Count total scans
     */
    public function count(): int
    {
        return (int) $this->db->fetchColumn('SELECT COUNT(*) FROM scans');
    }

    /**
     * Delete scan and its results
     */
    public function delete(int $id): bool
    {
        return $this->db->delete('scans', 'id = ?', [$id]) > 0;
    }

    /**
     * Delete old scans
     */
    public function deleteOlderThan(int $days): int
    {
        return $this->db->delete(
            'scans',
            'created_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
            [$days]
        );
    }

    /**
     * Get scan with all results
     */
    public function findWithResults(int $id): ?array
    {
        $scan = $this->find($id);
        if (!$scan) {
            return null;
        }

        $results = $this->db->fetchAll(
            'SELECT * FROM scan_results WHERE scan_id = ? ORDER BY id',
            [$id]
        );

        // Decode JSON details
        foreach ($results as &$result) {
            if (isset($result['details']) && is_string($result['details'])) {
                $result['details'] = json_decode($result['details'], true);
            }
        }

        $scan['results'] = $results;
        return $scan;
    }

    /**
     * Check if similar scan exists recently
     */
    public function findRecent(string $inputIdentifier, int $maxAgeMinutes = 5): ?array
    {
        $hash = hash('sha256', $inputIdentifier);
        return $this->db->fetchOne(
            'SELECT * FROM scans WHERE input_hash = ? AND status = ? AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE) ORDER BY created_at DESC LIMIT 1',
            [$hash, 'completed', $maxAgeMinutes]
        );
    }

    /**
     * Get recent scans for a specific user
     */
    public function getRecentByUser(int $userId, int $limit = 50, int $offset = 0): array
    {
        return $this->db->fetchAll(
            'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
            [$userId, $limit, $offset]
        );
    }

    /**
     * Count scans for a specific user
     */
    public function countByUser(int $userId): int
    {
        return (int) $this->db->fetchColumn(
            'SELECT COUNT(*) FROM scans WHERE user_id = ?',
            [$userId]
        );
    }

    /**
     * Find scan by ID with ownership check
     */
    public function findForUser(int $id, int $userId): ?array
    {
        return $this->db->fetchOne(
            'SELECT * FROM scans WHERE id = ? AND user_id = ?',
            [$id, $userId]
        );
    }

    /**
     * Find scan with results for a specific user
     */
    public function findWithResultsForUser(int $id, int $userId): ?array
    {
        $scan = $this->findForUser($id, $userId);
        if (!$scan) {
            return null;
        }

        $results = $this->db->fetchAll(
            'SELECT * FROM scan_results WHERE scan_id = ? ORDER BY id',
            [$id]
        );

        // Decode JSON details
        foreach ($results as &$result) {
            if (isset($result['details']) && is_string($result['details'])) {
                $result['details'] = json_decode($result['details'], true);
            }
        }

        $scan['results'] = $results;
        return $scan;
    }
}
