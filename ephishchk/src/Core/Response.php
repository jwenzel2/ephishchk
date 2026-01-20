<?php

declare(strict_types=1);

namespace Ephishchk\Core;

/**
 * HTTP Response wrapper
 */
class Response
{
    private int $statusCode;
    private array $headers = [];
    private string $body;

    public function __construct(string $body = '', int $statusCode = 200, array $headers = [])
    {
        $this->body = $body;
        $this->statusCode = $statusCode;
        $this->headers = $headers;
    }

    public static function html(string $content, int $statusCode = 200): self
    {
        return new self($content, $statusCode, ['Content-Type' => 'text/html; charset=utf-8']);
    }

    public static function json(mixed $data, int $statusCode = 200): self
    {
        return new self(
            json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
            $statusCode,
            ['Content-Type' => 'application/json; charset=utf-8']
        );
    }

    public static function redirect(string $url, int $statusCode = 302): self
    {
        $response = new self('', $statusCode);
        $response->setHeader('Location', $url);
        return $response;
    }

    public static function notFound(string $message = 'Not Found'): self
    {
        return new self($message, 404, ['Content-Type' => 'text/html; charset=utf-8']);
    }

    public static function error(string $message = 'Internal Server Error', int $statusCode = 500): self
    {
        return new self($message, $statusCode, ['Content-Type' => 'text/html; charset=utf-8']);
    }

    public function setStatusCode(int $statusCode): self
    {
        $this->statusCode = $statusCode;
        return $this;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    public function setHeader(string $name, string $value): self
    {
        $this->headers[$name] = $value;
        return $this;
    }

    public function getHeader(string $name): ?string
    {
        return $this->headers[$name] ?? null;
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function setBody(string $body): self
    {
        $this->body = $body;
        return $this;
    }

    public function getBody(): string
    {
        return $this->body;
    }

    public function appendBody(string $content): self
    {
        $this->body .= $content;
        return $this;
    }

    public function send(): void
    {
        // Send status code
        http_response_code($this->statusCode);

        // Send headers
        foreach ($this->headers as $name => $value) {
            header("$name: $value");
        }

        // Send body
        echo $this->body;
    }
}
