<?php

declare(strict_types=1);

namespace Ephishchk\Security;

/**
 * CSRF Protection using session-based tokens
 */
class CsrfProtection
{
    private const TOKEN_NAME = '_csrf_token';
    private const TOKEN_LENGTH = 32;

    public function __construct()
    {
        // Ensure session is started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Generate or retrieve the current CSRF token
     */
    public function getToken(): string
    {
        if (!isset($_SESSION[self::TOKEN_NAME])) {
            $_SESSION[self::TOKEN_NAME] = $this->generateToken();
        }

        return $_SESSION[self::TOKEN_NAME];
    }

    /**
     * Validate a submitted token against the stored token
     */
    public function validate(?string $token): bool
    {
        if ($token === null || $token === '') {
            return false;
        }

        $storedToken = $_SESSION[self::TOKEN_NAME] ?? null;

        if ($storedToken === null) {
            return false;
        }

        // Use timing-safe comparison
        return hash_equals($storedToken, $token);
    }

    /**
     * Regenerate the CSRF token (call after successful form submission)
     */
    public function regenerate(): string
    {
        $_SESSION[self::TOKEN_NAME] = $this->generateToken();
        return $_SESSION[self::TOKEN_NAME];
    }

    /**
     * Generate a cryptographically secure random token
     */
    private function generateToken(): string
    {
        return bin2hex(random_bytes(self::TOKEN_LENGTH));
    }

    /**
     * Get an HTML hidden input field with the CSRF token
     */
    public function getHiddenField(): string
    {
        $token = htmlspecialchars($this->getToken(), ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="' . self::TOKEN_NAME . '" value="' . $token . '">';
    }

    /**
     * Get the token name for form fields
     */
    public function getTokenName(): string
    {
        return self::TOKEN_NAME;
    }
}
