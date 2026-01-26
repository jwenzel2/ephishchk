<?php

declare(strict_types=1);

namespace Ephishchk\Controllers;

use Ephishchk\Core\Response;
use Ephishchk\Models\User;
use Ephishchk\Models\SafeDomain;
use Ephishchk\Security\InputSanitizer;

/**
 * Admin Controller - User Management
 */
class AdminController extends BaseController
{
    /**
     * List all users
     */
    public function users(): Response
    {
        if ($redirect = $this->requireAdmin()) {
            return $redirect;
        }

        $page = InputSanitizer::positiveInt($this->getQuery('page'), 1);
        $perPage = 20;
        $offset = ($page - 1) * $perPage;

        $userModel = new User($this->app->getDatabase());
        $users = $userModel->getAll($perPage, $offset);
        $total = $userModel->count();
        $totalPages = (int) ceil($total / $perPage);

        return $this->render('admin/users', [
            'title' => 'User Management',
            'users' => $users,
            'page' => $page,
            'totalPages' => $totalPages,
            'total' => $total,
        ]);
    }

    /**
     * Update user role
     */
    public function updateRole(): Response
    {
        if ($redirect = $this->requireAdmin()) {
            return $redirect;
        }

        $userId = InputSanitizer::positiveInt($this->getPost('user_id'), 0);
        $role = InputSanitizer::string($this->getPost('role', ''));

        if ($userId === 0) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Invalid user ID'], 400);
            }
            return $this->redirect('/admin/users');
        }

        if (!in_array($role, ['user', 'admin'])) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Invalid role'], 400);
            }
            return $this->redirect('/admin/users');
        }

        // Prevent admin from changing their own role
        if ($userId === $this->getUserId()) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'You cannot change your own role'], 400);
            }
            return $this->redirect('/admin/users');
        }

        $userModel = new User($this->app->getDatabase());
        $userModel->setRole($userId, $role);

        if ($this->isAjax()) {
            return $this->json(['success' => true, 'role' => $role]);
        }

        return $this->redirect('/admin/users');
    }

    /**
     * Toggle user active status
     */
    public function toggleActive(): Response
    {
        if ($redirect = $this->requireAdmin()) {
            return $redirect;
        }

        $userId = InputSanitizer::positiveInt($this->getPost('user_id'), 0);

        if ($userId === 0) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Invalid user ID'], 400);
            }
            return $this->redirect('/admin/users');
        }

        // Prevent admin from deactivating themselves
        if ($userId === $this->getUserId()) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'You cannot deactivate your own account'], 400);
            }
            return $this->redirect('/admin/users');
        }

        $userModel = new User($this->app->getDatabase());
        $user = $userModel->find($userId);

        if (!$user) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'User not found'], 404);
            }
            return $this->redirect('/admin/users');
        }

        $newStatus = $user['is_active'] ? 0 : 1;
        $userModel->update($userId, ['is_active' => $newStatus]);

        if ($this->isAjax()) {
            return $this->json(['success' => true, 'is_active' => $newStatus]);
        }

        return $this->redirect('/admin/users');
    }

    /**
     * Safe Domains Management Page
     */
    public function safeDomains(): Response
    {
        if ($redirect = $this->requireAdmin()) {
            return $redirect;
        }

        $safeDomainModel = new SafeDomain($this->app->getDatabase());
        $domains = $safeDomainModel->getAll();

        $data = [
            'title' => 'Safe Domains Management',
            'domains' => $domains,
            'total' => count($domains),
        ];

        // Add error/success messages from query params
        if ($error = $this->getQuery('error')) {
            $data['error'] = $error;
        }
        if ($success = $this->getQuery('success')) {
            $data['success'] = $success;
        }

        return $this->render('admin/safe-domains', $data);
    }

    /**
     * Add a safe domain (from management page)
     */
    public function addSafeDomain(): Response
    {
        if ($redirect = $this->requireAdmin()) {
            return $redirect;
        }

        $domain = InputSanitizer::string($this->getPost('domain', ''));
        $notes = InputSanitizer::string($this->getPost('notes', ''));

        // Debug: log raw input to file AND error_log
        $debugLog = "/tmp/safe_domain_debug.log";
        $timestamp = date('Y-m-d H:i:s');
        file_put_contents($debugLog, "[{$timestamp}] Raw POST domain: '" . ($this->getPost('domain', '') ?? 'NULL') . "'\n", FILE_APPEND);
        file_put_contents($debugLog, "[{$timestamp}] After sanitizer: '{$domain}' (length: " . strlen($domain) . ")\n", FILE_APPEND);

        error_log("[addSafeDomain] Raw POST domain: '" . ($this->getPost('domain', '') ?? 'NULL') . "'");
        error_log("[addSafeDomain] After sanitizer: '{$domain}' (length: " . strlen($domain) . ")");

        if (empty($domain) || trim($domain) === '') {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Domain is required'], 400);
            }
            return $this->redirect('/admin/safe-domains');
        }

        $safeDomainModel = new SafeDomain($this->app->getDatabase());

        // Check if domain already exists (exists() will normalize internally)
        if ($safeDomainModel->exists($domain)) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Domain already exists in safe list'], 400);
            }
            return $this->redirect('/admin/safe-domains?error=' . urlencode('Domain already exists'));
        }

        try {
            $safeDomainModel->create($domain, $this->getUserId(), $notes);
        } catch (\Exception $e) {
            error_log("[SafeDomain] Failed to create domain: " . $e->getMessage());
            if ($this->isAjax()) {
                return $this->json(['error' => 'Failed to add domain: ' . $e->getMessage()], 500);
            }
            return $this->redirect('/admin/safe-domains?error=' . urlencode('Failed to add domain'));
        }

        if ($this->isAjax()) {
            return $this->json(['success' => true, 'message' => 'Domain added successfully']);
        }

        return $this->redirect('/admin/safe-domains?success=' . urlencode('Domain added successfully'));
    }

    /**
     * Delete a safe domain
     */
    public function deleteSafeDomain(): Response
    {
        if ($redirect = $this->requireAdmin()) {
            return $redirect;
        }

        $id = InputSanitizer::positiveInt($this->getPost('id'), 0);

        if ($id === 0) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Invalid domain ID'], 400);
            }
            return $this->redirect('/admin/safe-domains');
        }

        $safeDomainModel = new SafeDomain($this->app->getDatabase());
        $safeDomainModel->delete($id);

        if ($this->isAjax()) {
            return $this->json(['success' => true, 'message' => 'Domain deleted successfully']);
        }

        return $this->redirect('/admin/safe-domains');
    }

    /**
     * Add domain from scan results (AJAX endpoint)
     */
    public function addDomainFromScan(): Response
    {
        if ($redirect = $this->requireAdmin()) {
            return $redirect;
        }

        $domain = InputSanitizer::string($this->getPost('domain', ''));

        // Log received domain for debugging
        error_log("[SafeDomain] Received domain from AJAX: '{$domain}'");

        if (empty($domain) || trim($domain) === '') {
            error_log("[SafeDomain] Domain is empty or whitespace");
            return $this->json(['error' => 'Domain is required'], 400);
        }

        $safeDomainModel = new SafeDomain($this->app->getDatabase());

        // Check if domain already exists (exists() will normalize internally)
        if ($safeDomainModel->exists($domain)) {
            error_log("[SafeDomain] Domain already exists: '{$normalizedDomain}'");
            return $this->json(['error' => 'Domain already in safe list'], 400);
        }

        $safeDomainModel->create($domain, $this->getUserId(), 'Added from scan results');
        error_log("[SafeDomain] Successfully added domain: '{$normalizedDomain}'");

        return $this->json([
            'success' => true,
            'message' => 'Domain added to safe list successfully'
        ]);
    }
}
