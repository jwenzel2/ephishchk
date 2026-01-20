<?php

declare(strict_types=1);

namespace Ephishchk\Security;

/**
 * Output encoding for XSS prevention
 */
class OutputEncoder
{
    /**
     * Encode for HTML content (default encoding)
     */
    public static function html(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Encode for use in HTML attributes
     */
    public static function attr(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Encode for use in JavaScript strings (within script tags)
     */
    public static function js(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        // JSON encode handles escaping for JS strings
        $encoded = json_encode($value, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);

        // Remove surrounding quotes added by json_encode
        return substr($encoded, 1, -1);
    }

    /**
     * Encode for use in URLs (query parameters)
     */
    public static function url(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        return rawurlencode($value);
    }

    /**
     * Encode for use in CSS strings
     */
    public static function css(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        // Escape characters that could break out of CSS string context
        $value = preg_replace_callback('/[^a-zA-Z0-9]/', function ($matches) {
            $char = $matches[0];
            return '\\' . dechex(ord($char)) . ' ';
        }, $value);

        return $value;
    }

    /**
     * Encode data for JSON output
     */
    public static function json(mixed $value, int $flags = 0): string
    {
        return json_encode($value, $flags | JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Encode array of values using HTML encoding
     */
    public static function htmlArray(array $values): array
    {
        return array_map([self::class, 'html'], $values);
    }

    /**
     * Create a safe link (validates URL scheme)
     */
    public static function safeUrl(?string $url): string
    {
        if ($url === null) {
            return '';
        }

        $parsed = parse_url($url);

        // Only allow safe schemes
        $safeSchemes = ['http', 'https', 'mailto'];

        if (isset($parsed['scheme']) && !in_array(strtolower($parsed['scheme']), $safeSchemes)) {
            return '';
        }

        return self::attr($url);
    }

    /**
     * Truncate and encode a string safely
     */
    public static function truncate(?string $value, int $length, string $suffix = '...'): string
    {
        if ($value === null) {
            return '';
        }

        if (mb_strlen($value) <= $length) {
            return self::html($value);
        }

        return self::html(mb_substr($value, 0, $length)) . $suffix;
    }

    /**
     * Format a date/time safely
     */
    public static function datetime(?string $value, string $format = 'Y-m-d H:i:s'): string
    {
        if ($value === null) {
            return '';
        }

        try {
            $dt = new \DateTime($value);
            return self::html($dt->format($format));
        } catch (\Exception) {
            return self::html($value);
        }
    }

    /**
     * Encode value for use in pre/code blocks (preserves whitespace)
     */
    public static function pre(?string $value): string
    {
        if ($value === null) {
            return '';
        }

        // Encode HTML entities but preserve whitespace
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE, 'UTF-8');
    }
}
