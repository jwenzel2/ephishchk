<?php

declare(strict_types=1);

namespace Ephishchk\Services\Scanner;

use Ephishchk\Services\Email\ParsedEmail;

/**
 * Link Extractor Service - extracts URLs from email content
 */
class LinkExtractorService
{
    private int $maxLinks;

    public function __construct(int $maxLinks = 50)
    {
        $this->maxLinks = $maxLinks;
    }

    /**
     * Extract all links from a parsed email
     *
     * @return array<int, array{url: string, text: ?string, source: string}>
     */
    public function extractFromEmail(ParsedEmail $email): array
    {
        $links = [];

        // Extract from HTML content
        $html = $email->getHtmlContent();
        if ($html) {
            $htmlLinks = $this->extractFromHtml($html);
            foreach ($htmlLinks as $link) {
                $link['source'] = 'html';
                $links[] = $link;
            }
        }

        // Extract from text content
        $text = $email->getTextContent();
        if ($text) {
            $textLinks = $this->extractFromText($text);
            foreach ($textLinks as $link) {
                // Avoid duplicates from HTML extraction
                $exists = false;
                foreach ($links as $existing) {
                    if ($existing['url'] === $link['url']) {
                        $exists = true;
                        break;
                    }
                }
                if (!$exists) {
                    $link['source'] = 'text';
                    $links[] = $link;
                }
            }
        }

        // Limit number of links
        if (count($links) > $this->maxLinks) {
            $links = array_slice($links, 0, $this->maxLinks);
        }

        return $links;
    }

    /**
     * Extract links from HTML content
     */
    public function extractFromHtml(string $html): array
    {
        $links = [];

        // Use DOMDocument to parse HTML
        $dom = new \DOMDocument();

        // Suppress warnings for malformed HTML
        libxml_use_internal_errors(true);
        $dom->loadHTML('<?xml encoding="UTF-8">' . $html, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        libxml_clear_errors();

        // Extract <a> tags
        $anchors = $dom->getElementsByTagName('a');
        foreach ($anchors as $anchor) {
            $href = $anchor->getAttribute('href');
            if ($href && $this->isValidUrl($href)) {
                $links[] = [
                    'url' => $this->normalizeUrl($href),
                    'text' => trim($anchor->textContent) ?: null,
                ];
            }
        }

        // Extract URLs from other attributes (img src, etc.)
        $images = $dom->getElementsByTagName('img');
        foreach ($images as $img) {
            $src = $img->getAttribute('src');
            if ($src && $this->isValidUrl($src)) {
                $links[] = [
                    'url' => $this->normalizeUrl($src),
                    'text' => 'Image: ' . ($img->getAttribute('alt') ?: 'unnamed'),
                ];
            }
        }

        return $links;
    }

    /**
     * Extract URLs from plain text
     */
    public function extractFromText(string $text): array
    {
        $links = [];

        // URL regex pattern
        $pattern = '/\bhttps?:\/\/[^\s<>\[\]"\']+/i';

        if (preg_match_all($pattern, $text, $matches)) {
            foreach ($matches[0] as $url) {
                // Clean up trailing punctuation
                $url = rtrim($url, '.,;:!?)>');
                $url = $this->normalizeUrl($url);

                if ($this->isValidUrl($url)) {
                    $links[] = [
                        'url' => $url,
                        'text' => null,
                    ];
                }
            }
        }

        // Also look for bare domains
        $domainPattern = '/\b(?:www\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/i';
        if (preg_match_all($domainPattern, $text, $matches)) {
            foreach ($matches[0] as $domain) {
                // Don't add if we already have a URL for this domain
                $found = false;
                foreach ($links as $link) {
                    if (str_contains($link['url'], $domain)) {
                        $found = true;
                        break;
                    }
                }

                if (!$found) {
                    $url = 'http://' . $domain;
                    $links[] = [
                        'url' => $url,
                        'text' => 'Bare domain',
                    ];
                }
            }
        }

        return array_unique($links, SORT_REGULAR);
    }

    /**
     * Check if URL is valid and worth analyzing
     */
    private function isValidUrl(string $url): bool
    {
        // Skip data: URLs, javascript:, mailto:, tel:, etc.
        if (preg_match('/^(data|javascript|mailto|tel|sms|ftp|file):/i', $url)) {
            return false;
        }

        // Skip anchors
        if (str_starts_with($url, '#')) {
            return false;
        }

        // Validate URL format
        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['host'])) {
            // Try adding http://
            $parsed = parse_url('http://' . $url);
        }

        return isset($parsed['host']) && strlen($parsed['host']) > 0;
    }

    /**
     * Normalize URL for consistent comparison
     */
    private function normalizeUrl(string $url): string
    {
        // Add scheme if missing
        if (!preg_match('/^https?:\/\//i', $url)) {
            $url = 'http://' . $url;
        }

        // Parse and rebuild
        $parts = parse_url($url);
        if (!$parts) {
            return $url;
        }

        $normalized = strtolower($parts['scheme'] ?? 'http') . '://';
        $normalized .= strtolower($parts['host'] ?? '');

        if (isset($parts['port']) && $parts['port'] != 80 && $parts['port'] != 443) {
            $normalized .= ':' . $parts['port'];
        }

        $normalized .= $parts['path'] ?? '/';

        if (isset($parts['query'])) {
            $normalized .= '?' . $parts['query'];
        }

        return $normalized;
    }

    /**
     * Extract domain from URL
     */
    public static function extractDomain(string $url): ?string
    {
        $parts = parse_url($url);
        return $parts['host'] ?? null;
    }
}
