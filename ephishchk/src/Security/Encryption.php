<?php

declare(strict_types=1);

namespace Ephishchk\Security;

/**
 * Encryption helper for sensitive data (API keys, etc.)
 */
class Encryption
{
    private const CIPHER = 'aes-256-gcm';
    private const TAG_LENGTH = 16;

    private string $key;

    public function __construct(string $key)
    {
        // Derive a proper key from the provided key
        $this->key = hash('sha256', $key, true);
    }

    /**
     * Encrypt a value
     */
    public function encrypt(string $value): string
    {
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));
        $tag = '';

        $encrypted = openssl_encrypt(
            $value,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH
        );

        if ($encrypted === false) {
            throw new \RuntimeException('Encryption failed');
        }

        // Combine IV + tag + ciphertext and encode
        return base64_encode($iv . $tag . $encrypted);
    }

    /**
     * Decrypt a value
     */
    public function decrypt(string $encryptedValue): string
    {
        $data = base64_decode($encryptedValue, true);

        if ($data === false) {
            throw new \RuntimeException('Invalid encrypted data format');
        }

        $ivLength = openssl_cipher_iv_length(self::CIPHER);

        if (strlen($data) < $ivLength + self::TAG_LENGTH) {
            throw new \RuntimeException('Invalid encrypted data length');
        }

        $iv = substr($data, 0, $ivLength);
        $tag = substr($data, $ivLength, self::TAG_LENGTH);
        $ciphertext = substr($data, $ivLength + self::TAG_LENGTH);

        $decrypted = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($decrypted === false) {
            throw new \RuntimeException('Decryption failed');
        }

        return $decrypted;
    }

    /**
     * Check if a value is encrypted (basic check for base64 format)
     */
    public static function isEncrypted(string $value): bool
    {
        // Check if it looks like base64-encoded data
        if (!preg_match('/^[A-Za-z0-9+\/]+=*$/', $value)) {
            return false;
        }

        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            return false;
        }

        // Check minimum length for IV + tag
        $ivLength = openssl_cipher_iv_length(self::CIPHER);
        return strlen($decoded) > $ivLength + self::TAG_LENGTH;
    }
}
