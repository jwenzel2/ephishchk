<?php

declare(strict_types=1);

namespace Ephishchk\Controllers;

use Ephishchk\Core\Response;
use Ephishchk\Models\User;
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
}
