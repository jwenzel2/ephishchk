<?php

declare(strict_types=1);

namespace Ephishchk\Models;

use Ephishchk\Core\Database;

/**
 * User Model
 */
class User
{
    private Database $db;

    private const BCRYPT_COST = 12;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Create a new user
     */
    public function create(string $email, string $password, ?string $displayName = null): int
    {
        $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => self::BCRYPT_COST]);

        return $this->db->insert('users', [
            'email' => strtolower(trim($email)),
            'password_hash' => $passwordHash,
            'display_name' => $displayName ? trim($displayName) : null,
        ]);
    }

    /**
     * Find user by ID
     */
    public function find(int $id): ?array
    {
        return $this->db->fetchOne('SELECT * FROM users WHERE id = ?', [$id]);
    }

    /**
     * Find user by email
     */
    public function findByEmail(string $email): ?array
    {
        return $this->db->fetchOne(
            'SELECT * FROM users WHERE email = ?',
            [strtolower(trim($email))]
        );
    }

    /**
     * Verify user password (timing-safe comparison via password_verify)
     */
    public function verifyPassword(array $user, string $password): bool
    {
        return password_verify($password, $user['password_hash']);
    }

    /**
     * Check if email already exists
     */
    public function emailExists(string $email): bool
    {
        return $this->findByEmail($email) !== null;
    }

    /**
     * Update last login timestamp
     */
    public function updateLastLogin(int $id): void
    {
        $this->db->query('UPDATE users SET last_login_at = NOW() WHERE id = ?', [$id]);
    }

    /**
     * Update user
     */
    public function update(int $id, array $data): void
    {
        $this->db->update('users', $data, 'id = ?', [$id]);
    }

    /**
     * Check if user is active
     */
    public function isActive(array $user): bool
    {
        return (bool) ($user['is_active'] ?? false);
    }
}
