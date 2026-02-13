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
    public function create(string $username, string $email, string $password): int
    {
        $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => self::BCRYPT_COST]);

        return $this->db->insert('users', [
            'username' => trim($username),
            'email' => strtolower(trim($email)),
            'password_hash' => $passwordHash,
            'display_name' => trim($username), // Username is also the display name
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
     * Find user by username
     */
    public function findByUsername(string $username): ?array
    {
        return $this->db->fetchOne(
            'SELECT * FROM users WHERE username = ?',
            [trim($username)]
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
     * Check if username already exists
     */
    public function usernameExists(string $username): bool
    {
        return $this->findByUsername($username) !== null;
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

    /**
     * Check if user is admin
     */
    public function isAdmin(array $user): bool
    {
        return ($user['role'] ?? 'user') === 'admin';
    }

    /**
     * Get user role
     */
    public function getRole(array $user): string
    {
        return $user['role'] ?? 'user';
    }

    /**
     * Set user role (admin only operation)
     */
    public function setRole(int $id, string $role): bool
    {
        if (!in_array($role, ['user', 'admin'])) {
            return false;
        }

        $this->db->update('users', ['role' => $role], 'id = ?', [$id]);
        return true;
    }

    /**
     * Get all users (for admin panel)
     */
    public function getAll(int $limit = 100, int $offset = 0): array
    {
        return $this->db->fetchAll(
            'SELECT id, username, email, display_name, role, is_active, created_at, last_login_at FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?',
            [$limit, $offset]
        );
    }

    /**
     * Count all users
     */
    public function count(): int
    {
        return (int) $this->db->fetchColumn('SELECT COUNT(*) FROM users');
    }
}
