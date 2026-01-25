<?php

declare(strict_types=1);

namespace Ephishchk\Controllers;

use Ephishchk\Core\Application;
use Ephishchk\Core\Request;
use Ephishchk\Core\Response;
use Ephishchk\Security\CsrfProtection;
use Ephishchk\Security\OutputEncoder;
use Ephishchk\Services\AuthService;
use Ephishchk\Models\User;
use Ephishchk\Models\UserPreference;

/**
 * Base Controller
 */
abstract class BaseController
{
    protected Application $app;
    protected Request $request;
    protected CsrfProtection $csrf;
    protected ?AuthService $authService = null;

    public function __construct(Application $app, Request $request)
    {
        $this->app = $app;
        $this->request = $request;
        $this->csrf = new CsrfProtection();
    }

    /**
     * Get AuthService instance
     */
    protected function auth(): AuthService
    {
        if ($this->authService === null) {
            $userModel = new User($this->app->getDatabase());
            $this->authService = new AuthService($userModel);
        }
        return $this->authService;
    }

    /**
     * Require authentication - redirects to login if not authenticated
     */
    protected function requireAuth(): ?Response
    {
        if (!$this->auth()->check()) {
            return $this->redirect('/login');
        }
        return null;
    }

    /**
     * Require admin role - redirects to home if not admin
     */
    protected function requireAdmin(): ?Response
    {
        if ($redirect = $this->requireAuth()) {
            return $redirect;
        }

        if (!$this->isAdmin()) {
            return $this->redirect('/');
        }
        return null;
    }

    /**
     * Get current user ID
     */
    protected function getUserId(): ?int
    {
        return $this->auth()->userId();
    }

    /**
     * Get current user data
     */
    protected function getUser(): ?array
    {
        return $this->auth()->user();
    }

    /**
     * Check if current user is admin
     */
    protected function isAdmin(): bool
    {
        $user = $this->getUser();
        return $user && ($user['role'] ?? 'user') === 'admin';
    }

    /**
     * Get current user's role
     */
    protected function getUserRole(): ?string
    {
        $user = $this->getUser();
        return $user ? ($user['role'] ?? 'user') : null;
    }

    /**
     * Render a template and return Response
     */
    protected function render(string $template, array $data = []): Response
    {
        // Add common data
        $data['csrfToken'] = $this->csrf->getToken();
        $data['csrfField'] = $this->csrf->getHiddenField();
        $data['currentUser'] = $this->getUser();

        // Load user preferences if logged in
        if ($this->getUserId()) {
            $prefModel = new UserPreference($this->app->getDatabase());
            $data['userPreferences'] = $prefModel->getAll($this->getUserId());
        } else {
            $data['userPreferences'] = [];
        }

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
