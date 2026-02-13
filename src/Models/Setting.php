<?php

declare(strict_types=1);

namespace Ephishchk\Models;

use Ephishchk\Core\Database;
use Ephishchk\Security\Encryption;

/**
 * Setting Model
 */
class Setting
{
    private Database $db;
    private ?Encryption $encryption;

    public function __construct(Database $db, ?string $encryptionKey = null)
    {
        $this->db = $db;
        $this->encryption = $encryptionKey ? new Encryption($encryptionKey) : null;
    }

    /**
     * Get a setting value
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $row = $this->db->fetchOne(
            'SELECT setting_value, setting_type, is_encrypted FROM settings WHERE setting_key = ?',
            [$key]
        );

        if (!$row) {
            return $default;
        }

        $value = $row['setting_value'];

        // Decrypt if needed
        if ($row['is_encrypted'] && $value && $this->encryption) {
            try {
                $value = $this->encryption->decrypt($value);
            } catch (\Exception) {
                return $default;
            }
        }

        // Cast to appropriate type
        return $this->castValue($value, $row['setting_type']);
    }

    /**
     * Set a setting value
     */
    public function set(string $key, mixed $value, ?string $type = null, bool $encrypted = false): void
    {
        // Get existing setting info
        $existing = $this->db->fetchOne(
            'SELECT setting_type, is_encrypted FROM settings WHERE setting_key = ?',
            [$key]
        );

        if ($existing) {
            $type = $type ?? $existing['setting_type'];
            $encrypted = $encrypted || (bool) $existing['is_encrypted'];
        }

        $type = $type ?? $this->detectType($value);

        // Convert value to string
        $stringValue = $this->valueToString($value, $type);

        // Encrypt if needed
        if ($encrypted && $stringValue && $this->encryption) {
            $stringValue = $this->encryption->encrypt($stringValue);
        }

        if ($existing) {
            $this->db->update(
                'settings',
                ['setting_value' => $stringValue, 'setting_type' => $type],
                'setting_key = ?',
                [$key]
            );
        } else {
            $this->db->insert('settings', [
                'setting_key' => $key,
                'setting_value' => $stringValue,
                'setting_type' => $type,
                'is_encrypted' => $encrypted ? 1 : 0,
            ]);
        }
    }

    /**
     * Get all settings
     */
    public function all(): array
    {
        $rows = $this->db->fetchAll('SELECT * FROM settings');
        $settings = [];

        foreach ($rows as $row) {
            $value = $row['setting_value'];

            // Decrypt if needed
            if ($row['is_encrypted'] && $value && $this->encryption) {
                try {
                    $value = $this->encryption->decrypt($value);
                } catch (\Exception) {
                    $value = null;
                }
            }

            $settings[$row['setting_key']] = [
                'value' => $this->castValue($value, $row['setting_type']),
                'type' => $row['setting_type'],
                'encrypted' => (bool) $row['is_encrypted'],
                'description' => $row['description'],
            ];
        }

        return $settings;
    }

    /**
     * Delete a setting
     */
    public function delete(string $key): bool
    {
        return $this->db->delete('settings', 'setting_key = ?', [$key]) > 0;
    }

    /**
     * Check if a setting exists
     */
    public function has(string $key): bool
    {
        $count = $this->db->fetchColumn(
            'SELECT COUNT(*) FROM settings WHERE setting_key = ?',
            [$key]
        );
        return $count > 0;
    }

    /**
     * Cast value to appropriate type
     */
    private function castValue(?string $value, string $type): mixed
    {
        if ($value === null) {
            return null;
        }

        return match ($type) {
            'integer' => (int) $value,
            'boolean' => filter_var($value, FILTER_VALIDATE_BOOLEAN),
            'json' => json_decode($value, true),
            default => $value,
        };
    }

    /**
     * Convert value to string for storage
     */
    private function valueToString(mixed $value, string $type): ?string
    {
        if ($value === null) {
            return null;
        }

        return match ($type) {
            'boolean' => $value ? '1' : '0',
            'json' => json_encode($value, JSON_UNESCAPED_UNICODE),
            default => (string) $value,
        };
    }

    /**
     * Detect type from value
     */
    private function detectType(mixed $value): string
    {
        if (is_bool($value)) {
            return 'boolean';
        }
        if (is_int($value)) {
            return 'integer';
        }
        if (is_array($value)) {
            return 'json';
        }
        return 'string';
    }
}
