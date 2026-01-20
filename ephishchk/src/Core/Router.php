<?php

declare(strict_types=1);

namespace Ephishchk\Core;

/**
 * Simple router with parameter support
 */
class Router
{
    private array $routes = [];

    public function addRoute(string $method, string $pattern, array $handler): void
    {
        $this->routes[] = [
            'method' => strtoupper($method),
            'pattern' => $pattern,
            'handler' => $handler,
        ];
    }

    public function loadRoutes(array $routes): void
    {
        foreach ($routes as $route) {
            $this->addRoute($route[0], $route[1], $route[2]);
        }
    }

    public function match(Request $request): ?array
    {
        $method = $request->getMethod();
        $path = $request->getPath();

        foreach ($this->routes as $route) {
            if ($route['method'] !== $method) {
                continue;
            }

            $params = $this->matchPattern($route['pattern'], $path);
            if ($params !== null) {
                return [
                    'handler' => $route['handler'],
                    'params' => $params,
                ];
            }
        }

        return null;
    }

    private function matchPattern(string $pattern, string $path): ?array
    {
        // Exact match
        if ($pattern === $path) {
            return [];
        }

        // Pattern with parameters
        $params = [];
        $patternParts = explode('/', trim($pattern, '/'));
        $pathParts = explode('/', trim($path, '/'));

        if (count($patternParts) !== count($pathParts)) {
            return null;
        }

        foreach ($patternParts as $i => $part) {
            // Parameter (e.g., {id})
            if (preg_match('/^\{(\w+)\}$/', $part, $matches)) {
                $params[$matches[1]] = $pathParts[$i];
                continue;
            }

            // Exact segment match
            if ($part !== $pathParts[$i]) {
                return null;
            }
        }

        return $params;
    }

    public function getRoutes(): array
    {
        return $this->routes;
    }
}
