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

        $email = InputSanitizer::string($this->getPost('email', ''));
        $password = $this->getPost('password', '');

        // Validate input
        if (empty($email) || empty($password)) {
            return $this->render('auth/login', [
                'title' => 'Login',
                'error' => 'Please enter your email and password',
                'email' => $email,
            ]);
        }

        // Validate email format
        if (!InputSanitizer::validateEmail($email)) {
            return $this->render('auth/login', [
                'title' => 'Login',
                'error' => 'Please enter a valid email address',
                'email' => $email,
            ]);
        }

        // Attempt login
        if ($this->auth()->attempt($email, $password)) {
            return $this->redirect('/');
        }

        return $this->render('auth/login', [
            'title' => 'Login',
            'error' => 'Invalid email or password',
            'email' => $email,
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

        $email = InputSanitizer::string($this->getPost('email', ''));
        $password = $this->getPost('password', '');
        $passwordConfirm = $this->getPost('password_confirm', '');
        $displayName = InputSanitizer::string($this->getPost('display_name', ''));

        // Validate input
        if (empty($email) || empty($password)) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => 'Please enter your email and password',
                'email' => $email,
                'displayName' => $displayName,
            ]);
        }

        // Validate email format
        if (!InputSanitizer::validateEmail($email)) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => 'Please enter a valid email address',
                'email' => $email,
                'displayName' => $displayName,
            ]);
        }

        // Validate password length
        if (strlen($password) < 8) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => 'Password must be at least 8 characters long',
                'email' => $email,
                'displayName' => $displayName,
            ]);
        }

        // Validate password confirmation
        if ($password !== $passwordConfirm) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => 'Passwords do not match',
                'email' => $email,
                'displayName' => $displayName,
            ]);
        }

        // Attempt registration
        $result = $this->auth()->register($email, $password, $displayName ?: null);

        if (isset($result['error'])) {
            return $this->render('auth/register', [
                'title' => 'Register',
                'error' => $result['error'],
                'email' => $email,
                'displayName' => $displayName,
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
