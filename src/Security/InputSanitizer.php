<?php

declare(strict_types=1);

namespace Ephishchk\Security;

/**
 * Input sanitization for user-provided data
 */
class InputSanitizer
{
    /**
     * Sanitize a string - removes null bytes and trims whitespace
     */
    public static function string(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        // Remove null bytes
        $value = str_replace("\0", '', $value);

        // Trim whitespace
        return trim($value);
    }

    /**
     * Sanitize an email address
     */
    public static function email(?string $value): string
    {
        $sanitized = self::string($value);
        return filter_var($sanitized, FILTER_SANITIZE_EMAIL) ?: '';
    }

    /**
     * Validate and return email if valid, empty string otherwise
     */
    public static function validateEmail(?string $value): string
    {
        $sanitized = self::email($value);
        return filter_var($sanitized, FILTER_VALIDATE_EMAIL) ?: '';
    }

    /**
     * Sanitize a domain name
     */
    public static function domain(?string $value): string
    {
        $sanitized = self::string($value);

        if ($sanitized === '') {
            return '';
        }

        // Remove protocol if present
        $sanitized = preg_replace('#^https?://#i', '', $sanitized);
        if ($sanitized === null) {
            return '';
        }

        // Remove path and query string
        $sanitized = preg_replace('#[/?#].*$#', '', $sanitized);
        if ($sanitized === null || $sanitized === '') {
            return '';
        }

        // Lowercase
        $sanitized = strtolower($sanitized);

        // Validate domain format
        if (!preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i', $sanitized)) {
            return '';
        }

        return $sanitized;
    }

    /**
     * Sanitize a URL
     */
    public static function url(?string $value): string
    {
        $sanitized = self::string($value);
        return filter_var($sanitized, FILTER_SANITIZE_URL) ?: '';
    }

    /**
     * Validate and return URL if valid
     */
    public static function validateUrl(?string $value): string
    {
        $sanitized = self::url($value);
        $validated = filter_var($sanitized, FILTER_VALIDATE_URL);
        return $validated ?: '';
    }

    /**
     * Sanitize an integer
     */
    public static function integer(?string $value, int $default = 0): int
    {
        if ($value === null) {
            return $default;
        }

        $filtered = filter_var($value, FILTER_VALIDATE_INT);
        return $filtered !== false ? $filtered : $default;
    }

    /**
     * Sanitize a positive integer
     */
    public static function positiveInt(?string $value, int $default = 0): int
    {
        $result = self::integer($value, $default);
        return $result > 0 ? $result : $default;
    }

    /**
     * Sanitize a boolean
     */
    public static function boolean(mixed $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Sanitize raw email content (preserves structure but removes dangerous elements)
     */
    public static function rawEmail(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        // Remove null bytes
        $value = str_replace("\0", '', $value);

        // Normalize line endings
        $value = str_replace(["\r\n", "\r"], "\n", $value);

        return $value;
    }

    /**
     * Sanitize an IP address
     */
    public static function ipAddress(?string $value): string
    {
        $sanitized = self::string($value);
        $validated = filter_var($sanitized, FILTER_VALIDATE_IP);
        return $validated ?: '';
    }

    /**
     * Sanitize a filename (remove path traversal attempts)
     */
    public static function filename(?string $value): string
    {
        $sanitized = self::string($value);

        // Remove path traversal characters
        $sanitized = str_replace(['..', '/', '\\'], '', $sanitized);

        // Remove control characters
        $sanitized = preg_replace('/[\x00-\x1f\x7f]/', '', $sanitized);

        return $sanitized;
    }

    /**
     * Sanitize array of values using a callback
     */
    public static function array(array $values, callable $sanitizer): array
    {
        return array_map($sanitizer, $values);
    }
}
