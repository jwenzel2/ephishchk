<?php

declare(strict_types=1);

namespace Ephishchk\Models;

use Ephishchk\Core\Database;

/**
 * ScanResult Model
 */
class ScanResult
{
    private Database $db;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Create a new scan result
     */
    public function create(array $data): int
    {
        $details = $data['details'] ?? null;
        if (is_array($details)) {
            $details = json_encode($details, JSON_UNESCAPED_UNICODE);
        }

        return $this->db->insert('scan_results', [
            'scan_id' => $data['scan_id'],
            'check_type' => $data['check_type'],
            'status' => $data['status'],
            'score' => $data['score'] ?? null,
            'summary' => $data['summary'],
            'details' => $details,
        ]);
    }

    /**
     * Update a scan result
     */
    public function update(int $id, array $data): bool
    {
        $updateData = [];

        if (isset($data['status'])) {
            $updateData['status'] = $data['status'];
        }
        if (isset($data['score'])) {
            $updateData['score'] = $data['score'];
        }
        if (isset($data['summary'])) {
            $updateData['summary'] = $data['summary'];
        }
        if (isset($data['details'])) {
            $details = $data['details'];
            if (is_array($details)) {
                $details = json_encode($details, JSON_UNESCAPED_UNICODE);
            }
            $updateData['details'] = $details;
        }

        if (empty($updateData)) {
            return false;
        }

        return $this->db->update('scan_results', $updateData, 'id = ?', [$id]) > 0;
    }

    /**
     * Get results for a scan
     */
    public function getByScanId(int $scanId): array
    {
        $results = $this->db->fetchAll(
            'SELECT * FROM scan_results WHERE scan_id = ? ORDER BY id',
            [$scanId]
        );

        // Decode JSON details
        foreach ($results as &$result) {
            if (isset($result['details']) && is_string($result['details'])) {
                $result['details'] = json_decode($result['details'], true);
            }
        }

        return $results;
    }

    /**
     * Get results by check type
     */
    public function getByCheckType(int $scanId, string $checkType): array
    {
        $results = $this->db->fetchAll(
            'SELECT * FROM scan_results WHERE scan_id = ? AND check_type = ?',
            [$scanId, $checkType]
        );

        foreach ($results as &$result) {
            if (isset($result['details']) && is_string($result['details'])) {
                $result['details'] = json_decode($result['details'], true);
            }
        }

        return $results;
    }

    /**
     * Delete results for a scan
     */
    public function deleteByScanId(int $scanId): int
    {
        return $this->db->delete('scan_results', 'scan_id = ?', [$scanId]);
    }

    /**
     * Count results by status
     */
    public function countByStatus(int $scanId): array
    {
        $results = $this->db->fetchAll(
            'SELECT status, COUNT(*) as count FROM scan_results WHERE scan_id = ? GROUP BY status',
            [$scanId]
        );

        $counts = ['pass' => 0, 'fail' => 0, 'warning' => 0, 'info' => 0, 'error' => 0];
        foreach ($results as $row) {
            $counts[$row['status']] = (int) $row['count'];
        }

        return $counts;
    }
}
