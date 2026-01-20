<?php

declare(strict_types=1);

namespace Ephishchk\Services\Email;

use ZBateson\MailMimeParser\MailMimeParser;
use ZBateson\MailMimeParser\Message;
use ZBateson\MailMimeParser\Header\HeaderConsts;

/**
 * Email Parser Service - wrapper around zbateson/mail-mime-parser
 */
class EmailParserService
{
    private MailMimeParser $parser;

    public function __construct()
    {
        $this->parser = new MailMimeParser();
    }

    /**
     * Parse raw email content
     */
    public function parse(string $rawEmail): ?ParsedEmail
    {
        try {
            $message = $this->parser->parse($rawEmail, false);

            if ($message === null) {
                return null;
            }

            return new ParsedEmail($message);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Parse email from file
     */
    public function parseFile(string $filePath): ?ParsedEmail
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            return null;
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            return null;
        }

        return $this->parse($content);
    }
}

/**
 * Parsed Email wrapper class
 */
class ParsedEmail
{
    private Message $message;

    public function __construct(Message $message)
    {
        $this->message = $message;
    }

    /**
     * Get the underlying message object
     */
    public function getMessage(): Message
    {
        return $this->message;
    }

    /**
     * Get all headers as array
     */
    public function getHeaders(): array
    {
        $headers = [];

        foreach ($this->message->getAllHeaders() as $header) {
            $name = $header->getName();
            $value = $header->getRawValue();

            if (!isset($headers[$name])) {
                $headers[$name] = [];
            }
            $headers[$name][] = $value;
        }

        return $headers;
    }

    /**
     * Get a specific header value
     */
    public function getHeader(string $name): ?string
    {
        $header = $this->message->getHeader($name);
        return $header ? $header->getRawValue() : null;
    }

    /**
     * Get all values for a header (handles multiple occurrences)
     */
    public function getHeaderValues(string $name): array
    {
        $values = [];
        foreach ($this->message->getAllHeadersByName($name) as $header) {
            $values[] = $header->getRawValue();
        }
        return $values;
    }

    /**
     * Get From address
     */
    public function getFrom(): ?array
    {
        $header = $this->message->getHeader(HeaderConsts::FROM);
        if (!$header) {
            return null;
        }

        $addresses = $header->getAddresses();
        if (empty($addresses)) {
            return null;
        }

        $addr = $addresses[0];
        return [
            'email' => $addr->getEmail(),
            'name' => $addr->getName(),
        ];
    }

    /**
     * Get all To addresses
     */
    public function getTo(): array
    {
        return $this->getAddressHeader(HeaderConsts::TO);
    }

    /**
     * Get all CC addresses
     */
    public function getCc(): array
    {
        return $this->getAddressHeader(HeaderConsts::CC);
    }

    /**
     * Get Reply-To address
     */
    public function getReplyTo(): ?array
    {
        $header = $this->message->getHeader(HeaderConsts::REPLY_TO);
        if (!$header) {
            return null;
        }

        $addresses = $header->getAddresses();
        if (empty($addresses)) {
            return null;
        }

        $addr = $addresses[0];
        return [
            'email' => $addr->getEmail(),
            'name' => $addr->getName(),
        ];
    }

    /**
     * Get Subject
     */
    public function getSubject(): ?string
    {
        $header = $this->message->getHeader(HeaderConsts::SUBJECT);
        return $header ? $header->getValue() : null;
    }

    /**
     * Get Date
     */
    public function getDate(): ?\DateTimeImmutable
    {
        $header = $this->message->getHeader(HeaderConsts::DATE);
        if (!$header) {
            return null;
        }

        try {
            $dateTime = $header->getDateTime();
            if ($dateTime === null) {
                return null;
            }
            // Convert DateTime to DateTimeImmutable if needed
            if ($dateTime instanceof \DateTimeImmutable) {
                return $dateTime;
            }
            return \DateTimeImmutable::createFromMutable($dateTime);
        } catch (\Exception) {
            return null;
        }
    }

    /**
     * Get Message-ID
     */
    public function getMessageId(): ?string
    {
        return $this->getHeader('Message-ID');
    }

    /**
     * Get plain text content
     */
    public function getTextContent(): ?string
    {
        return $this->message->getTextContent();
    }

    /**
     * Get HTML content
     */
    public function getHtmlContent(): ?string
    {
        return $this->message->getHtmlContent();
    }

    /**
     * Get all Received headers (in order)
     */
    public function getReceivedHeaders(): array
    {
        return $this->getHeaderValues('Received');
    }

    /**
     * Get authentication results header
     */
    public function getAuthenticationResults(): ?string
    {
        return $this->getHeader('Authentication-Results');
    }

    /**
     * Get DKIM signature header
     */
    public function getDkimSignature(): ?string
    {
        return $this->getHeader('DKIM-Signature');
    }

    /**
     * Get Return-Path
     */
    public function getReturnPath(): ?string
    {
        $header = $this->message->getHeader('Return-Path');
        if (!$header) {
            return null;
        }

        // Extract email from angle brackets if present
        $value = $header->getRawValue();
        if (preg_match('/<([^>]+)>/', $value, $matches)) {
            return $matches[1];
        }
        return trim($value);
    }

    /**
     * Get all attachments
     */
    public function getAttachments(): array
    {
        $attachments = [];

        $count = $this->message->getAttachmentCount();
        for ($i = 0; $i < $count; $i++) {
            $part = $this->message->getAttachmentPart($i);
            if ($part === null) {
                continue;
            }

            $attachments[] = [
                'filename' => $part->getFilename() ?? 'attachment_' . $i,
                'content_type' => $part->getContentType(),
                'size' => strlen($part->getContent() ?? ''),
                'content' => $part->getContent(),
            ];
        }

        return $attachments;
    }

    /**
     * Get attachment count
     */
    public function getAttachmentCount(): int
    {
        return $this->message->getAttachmentCount();
    }

    /**
     * Check if email has attachments
     */
    public function hasAttachments(): bool
    {
        return $this->message->getAttachmentCount() > 0;
    }

    /**
     * Extract domain from email address
     */
    public function getSenderDomain(): ?string
    {
        $from = $this->getFrom();
        if (!$from || empty($from['email'])) {
            return null;
        }

        $parts = explode('@', $from['email']);
        return count($parts) === 2 ? strtolower($parts[1]) : null;
    }

    /**
     * Get addresses from an address header
     */
    private function getAddressHeader(string $headerName): array
    {
        $header = $this->message->getHeader($headerName);
        if (!$header) {
            return [];
        }

        $addresses = [];
        foreach ($header->getAddresses() as $addr) {
            $addresses[] = [
                'email' => $addr->getEmail(),
                'name' => $addr->getName(),
            ];
        }

        return $addresses;
    }

    /**
     * Get X-Originating-IP if present
     */
    public function getOriginatingIp(): ?string
    {
        $header = $this->getHeader('X-Originating-IP');
        if (!$header) {
            return null;
        }

        // Extract IP from brackets if present
        if (preg_match('/\[([^\]]+)\]/', $header, $matches)) {
            return $matches[1];
        }

        return trim($header);
    }

    /**
     * Get X-Mailer header
     */
    public function getMailer(): ?string
    {
        return $this->getHeader('X-Mailer');
    }
}
