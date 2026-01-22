<?php

declare(strict_types=1);

namespace Ephishchk\Core;

use Ephishchk\Security\CsrfProtection;

/**
 * Main application class - bootstraps and handles requests
 */
class Application
{
    private array $config;
    private Router $router;
    private ?Database $database = null;
    private array $services = [];

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->router = new Router();

        // Load routes
        $routes = require BASE_PATH . '/config/routes.php';
        $this->router->loadRoutes($routes);

        // Create storage directories if they don't exist
        $this->ensureDirectories();
    }

    private function ensureDirectories(): void
    {
        $directories = [
            $this->config['paths']['storage'],
            $this->config['paths']['logs'],
            $this->config['paths']['cache'],
            $this->config['paths']['temp'],
        ];

        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
        }
    }

    public function getConfig(string $key = null): mixed
    {
        if ($key === null) {
            return $this->config;
        }

        $keys = explode('.', $key);
        $value = $this->config;

        foreach ($keys as $k) {
            if (!isset($value[$k])) {
                return null;
            }
            $value = $value[$k];
        }

        return $value;
    }

    public function getDatabase(): Database
    {
        if ($this->database === null) {
            $dbConfig = require BASE_PATH . '/config/database.php';
            $this->database = Database::getInstance($dbConfig);
        }
        return $this->database;
    }

    public function getRouter(): Router
    {
        return $this->router;
    }

    public function setService(string $name, object $service): void
    {
        $this->services[$name] = $service;
    }

    public function getService(string $name): ?object
    {
        return $this->services[$name] ?? null;
    }

    public function handle(Request $request): Response
    {
        // Match route
        $match = $this->router->match($request);

        if ($match === null) {
            return $this->renderNotFound();
        }

        // Add route parameters to request
        foreach ($match['params'] as $key => $value) {
            $request->setAttribute($key, $value);
        }

        // Resolve controller and method
        [$controllerClass, $method] = $match['handler'];

        if (!class_exists($controllerClass)) {
            return Response::error("Controller not found: $controllerClass", 500);
        }

        // Create controller instance
        $controller = new $controllerClass($this, $request);

        if (!method_exists($controller, $method)) {
            return Response::error("Method not found: $method", 500);
        }

        // CSRF protection for POST requests
        if ($request->isPost()) {
            $csrf = new CsrfProtection();
            if (!$csrf->validate($request->getPost('_csrf_token', ''))) {
                return Response::error('Invalid CSRF token', 403);
            }
        }

        // Call controller method
        return $controller->$method();
    }

    private function renderNotFound(): Response
    {
        $templatePath = $this->config['paths']['templates'] . '/errors/404.php';

        if (file_exists($templatePath)) {
            ob_start();
            include $templatePath;
            $content = ob_get_clean();
            return Response::html($content, 404);
        }

        return Response::notFound('Page not found');
    }

    public function render(string $template, array $data = []): string
    {
        $templatePath = $this->config['paths']['templates'] . '/' . $template . '.php';

        if (!file_exists($templatePath)) {
            throw new \RuntimeException("Template not found: $template");
        }

        // Extract data to variables
        extract($data);

        // Add CSRF token helper
        $csrf = new CsrfProtection();
        $csrfToken = $csrf->getToken();
        $csrfField = '<input type="hidden" name="_csrf_token" value="' . htmlspecialchars($csrfToken) . '">';

        // Start output buffering
        ob_start();
        include $templatePath;
        return ob_get_clean();
    }
}
