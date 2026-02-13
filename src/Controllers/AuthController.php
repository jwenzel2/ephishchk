<?php

declare(strict_types=1);

namespace Ephishchk\Controllers;

use Ephishchk\Core\Response;
use Ephishchk\Security\InputSanitizer;

/**
 * Authentication Controller
 */
class AuthController extends BaseController
{
    /**
     * Show login form
     */
    public function showLogin(): Response
    {
        // Redirect if already logged in
        if ($this->auth()->check()) {
            return $this->redirect('/');
        }

        return $this->render('auth/login', [
            'title' => 'Login',
        ]);
    }

    /**
     * Process login
     */
    public function login(): Response
    {
        // Redirect if already logged in
        if ($this->auth()->check()) {
            return $this->redirect('/');
        }

        $username = InputSanitizer::string($this->getPost('username', ''));
        $password = $this->getPost('password', '');

        // Validate input
        if (empty($username) || empty($password)) {
            return $this->render('auth/login', [
                'title' => 'Login',
                'error' => 'Please enter your username and password',
                'username' => $username,
            ]);
        }

        // Attempt login
        if ($this->auth()->attemptUsername($username, $password)) {
            return $this->redirect('/');
        }

        return $this->render('auth/login', [
            'title' => 'Login',
            'error' => 'Invalid username or password',
            'username' => $username,
        ]);
    }

    /**
     * Show registration form
     */
    public function showRegister(): Response
    {
        // Redirect if already logged in
        if ($this->auth()->check()) {
            return $this->redirect('/');
        }

        return $this->render('auth/register', [
            'title' => 'Register',
        ]);
    }

    /**
     * Process registration
     */
    public function register(): Response
    {
        // Redirect if already logged in
        if ($this->auth()->check()) {
            return $this->redirect('/');
        }

        $username = InputSanitizer::string($this->getPost('username', ''));
        $email = InputSanitizer::string($this->getPost('email', ''));
        $password = $this->getPost('password', '');
        $passwordConfirm = $this->getPost('password_confirm', '');

        // Validate input
        if (empty($username) || empty($email) || empty($password)) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => 'Please fill in all required fields',
                'username' => $username,
                'email' => $email,
            ]);
        }

        // Validate username format (alphanumeric, underscores, hyphens, 3-50 chars)
        if (!preg_match('/^[a-zA-Z0-9_-]{3,50}$/', $username)) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => 'Username must be 3-50 characters and contain only letters, numbers, underscores, or hyphens',
                'username' => $username,
                'email' => $email,
            ]);
        }

        // Validate email format
        if (!InputSanitizer::validateEmail($email)) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => 'Please enter a valid email address',
                'username' => $username,
                'email' => $email,
            ]);
        }

        // Validate password length
        if (strlen($password) < 8) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => 'Password must be at least 8 characters long',
                'username' => $username,
                'email' => $email,
            ]);
        }

        // Validate password confirmation
        if ($password !== $passwordConfirm) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => 'Passwords do not match',
                'username' => $username,
                'email' => $email,
            ]);
        }

        // Attempt registration
        $result = $this->auth()->registerWithUsername($username, $email, $password);

        if (isset($result['error'])) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => $result['error'],
                'username' => $username,
                'email' => $email,
            ]);
        }

        return $this->redirect('/');
    }

    /**
     * Process logout
     */
    public function logout(): Response
    {
        $this->auth()->logout();
        return $this->redirect('/login');
    }
}
