<?php

declare(strict_types=1);

namespace Ephishchk\Services;

use Ephishchk\Models\User;

/**
 * Authentication Service
 */
class AuthService
{
    private User $userModel;

    private const SESSION_USER_ID = '_user_id';
    private const SESSION_USER_DATA = '_user_data';

    public function __construct(User $userModel)
    {
        $this->userModel = $userModel;
        $this->ensureSessionStarted();
    }

    /**
     * Ensure session is started
     */
    private function ensureSessionStarted(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Attempt to log in with email and password
     */
    public function attempt(string $email, string $password): bool
    {
        $user = $this->userModel->findByEmail($email);

        if (!$user) {
            return false;
        }

        if (!$this->userModel->isActive($user)) {
            return false;
        }

        if (!$this->userModel->verifyPassword($user, $password)) {
            return false;
        }

        // Login successful
        $this->createSession($user);
        $this->userModel->updateLastLogin($user['id']);

        return true;
    }

    /**
     * Check if user is logged in
     */
    public function check(): bool
    {
        return isset($_SESSION[self::SESSION_USER_ID]);
    }

    /**
     * Get current user ID
     */
    public function userId(): ?int
    {
        return isset($_SESSION[self::SESSION_USER_ID])
            ? (int) $_SESSION[self::SESSION_USER_ID]
            : null;
    }

    /**
     * Get current user data (cached in session)
     */
    public function user(): ?array
    {
        if (!$this->check()) {
            return null;
        }

        // Return cached user data
        if (isset($_SESSION[self::SESSION_USER_DATA])) {
            return $_SESSION[self::SESSION_USER_DATA];
        }

        // Fetch fresh user data
        $user = $this->userModel->find($this->userId());
        if ($user) {
            unset($user['password_hash']);
            $_SESSION[self::SESSION_USER_DATA] = $user;
        }

        return $user;
    }

    /**
     * Logout current user
     */
    public function logout(): void
    {
        unset($_SESSION[self::SESSION_USER_ID]);
        unset($_SESSION[self::SESSION_USER_DATA]);

        // Regenerate session ID to prevent session fixation
        session_regenerate_id(true);
    }

    /**
     * Register a new user and auto-login
     */
    public function register(string $email, string $password, ?string $displayName = null): array
    {
        // Check if email already exists
        if ($this->userModel->emailExists($email)) {
            return ['error' => 'Email address is already registered'];
        }

        // Create user
        $userId = $this->userModel->create($email, $password, $displayName);

        // Fetch the created user
        $user = $this->userModel->find($userId);

        // Auto-login
        $this->createSession($user);
        $this->userModel->updateLastLogin($userId);

        return ['success' => true, 'user_id' => $userId];
    }

    /**
     * Create session for user
     */
    private function createSession(array $user): void
    {
        // Regenerate session ID to prevent session fixation
        session_regenerate_id(true);

        $_SESSION[self::SESSION_USER_ID] = $user['id'];

        // Cache user data without sensitive fields
        $userData = $user;
        unset($userData['password_hash']);
        $_SESSION[self::SESSION_USER_DATA] = $userData;
    }

    /**
     * Refresh user data in session
     */
    public function refreshUser(): void
    {
        if (!$this->check()) {
            return;
        }

        $user = $this->userModel->find($this->userId());
        if ($user) {
            unset($user['password_hash']);
            $_SESSION[self::SESSION_USER_DATA] = $user;
        }
    }
}
