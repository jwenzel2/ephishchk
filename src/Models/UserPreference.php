<?php

declare(strict_types=1);

namespace Ephishchk\Models;

use Ephishchk\Core\Database;

/**
 * User Preference Model
 */
class UserPreference
{
    private Database $db;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Get a preference value for a user
     */
    public function get(int $userId, string $key, mixed $default = null): mixed
    {
        $result = $this->db->fetchOne(
            'SELECT preference_value FROM user_preferences WHERE user_id = ? AND preference_key = ?',
            [$userId, $key]
        );

        if ($result === null) {
            return $default;
        }

        return $result['preference_value'];
    }

    /**
     * Set a preference value for a user
     */
    public function set(int $userId, string $key, mixed $value): void
    {
        $exists = $this->db->fetchOne(
            'SELECT id FROM user_preferences WHERE user_id = ? AND preference_key = ?',
            [$userId, $key]
        );

        if ($exists) {
            $this->db->update(
                'user_preferences',
                ['preference_value' => $value],
                'user_id = ? AND preference_key = ?',
                [$userId, $key]
            );
        } else {
            $this->db->insert('user_preferences', [
                'user_id' => $userId,
                'preference_key' => $key,
                'preference_value' => $value,
            ]);
        }
    }

    /**
     * Get all preferences for a user
     */
    public function getAll(int $userId): array
    {
        $rows = $this->db->fetchAll(
            'SELECT preference_key, preference_value FROM user_preferences WHERE user_id = ?',
            [$userId]
        );

        $preferences = [];
        foreach ($rows as $row) {
            $preferences[$row['preference_key']] = $row['preference_value'];
        }

        return $preferences;
    }

    /**
     * Delete a preference
     */
    public function delete(int $userId, string $key): void
    {
        $this->db->query(
            'DELETE FROM user_preferences WHERE user_id = ? AND preference_key = ?',
            [$userId, $key]
        );
    }

    /**
     * Delete all preferences for a user
     */
    public function deleteAll(int $userId): void
    {
        $this->db->query('DELETE FROM user_preferences WHERE user_id = ?', [$userId]);
    }
}
