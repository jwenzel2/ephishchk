<?php

declare(strict_types=1);

namespace Ephishchk\Controllers;

use Ephishchk\Core\Application;
use Ephishchk\Core\Request;
use Ephishchk\Core\Response;
use Ephishchk\Security\CsrfProtection;
use Ephishchk\Security\OutputEncoder;

/**
 * Base Controller
 */
abstract class BaseController
{
    protected Application $app;
    protected Request $request;
    protected CsrfProtection $csrf;

    public function __construct(Application $app, Request $request)
    {
        $this->app = $app;
        $this->request = $request;
        $this->csrf = new CsrfProtection();
    }

    /**
     * Render a template and return Response
     */
    protected function render(string $template, array $data = []): Response
    {
        // Add common data
        $data['csrfToken'] = $this->csrf->getToken();
        $data['csrfField'] = $this->csrf->getHiddenField();

        $content = $this->app->render($template, $data);
        return Response::html($content);
    }

    /**
     * Return JSON response
     */
    protected function json(mixed $data, int $statusCode = 200): Response
    {
        return Response::json($data, $statusCode);
    }

    /**
     * Redirect to URL
     */
    protected function redirect(string $url): Response
    {
        return Response::redirect($url);
    }

    /**
     * Get route parameter
     */
    protected function getParam(string $name, mixed $default = null): mixed
    {
        return $this->request->getAttribute($name, $default);
    }

    /**
     * Get POST data
     */
    protected function getPost(string $key = null, mixed $default = null): mixed
    {
        return $this->request->getPost($key, $default);
    }

    /**
     * Get GET parameter
     */
    protected function getQuery(string $key = null, mixed $default = null): mixed
    {
        return $this->request->getQuery($key, $default);
    }

    /**
     * Check if request is AJAX
     */
    protected function isAjax(): bool
    {
        return $this->request->isAjax();
    }

    /**
     * Output encode helper
     */
    protected function e(string $value): string
    {
        return OutputEncoder::html($value);
    }
}
