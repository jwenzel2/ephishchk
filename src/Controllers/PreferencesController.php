<?php

declare(strict_types=1);

namespace Ephishchk\Controllers;

use Ephishchk\Core\Response;
use Ephishchk\Models\UserPreference;
use Ephishchk\Models\User;
use Ephishchk\Security\InputSanitizer;

/**
 * User Preferences Controller
 */
class PreferencesController extends BaseController
{
    /**
     * Display user preferences page
     */
    public function index(): Response
    {
        if ($redirect = $this->requireAuth()) {
            return $redirect;
        }

        $prefModel = new UserPreference($this->app->getDatabase());
        $preferences = $prefModel->getAll($this->getUserId());

        $user = $this->getUser();

        return $this->render('preferences/index', [
            'title' => 'My Preferences',
            'preferences' => $preferences,
            'userRole' => $user['role'] ?? 'user',
        ]);
    }

    /**
     * Save user preferences
     */
    public function save(): Response
    {
        if ($redirect = $this->requireAuth()) {
            return $redirect;
        }

        $prefModel = new UserPreference($this->app->getDatabase());
        $userId = $this->getUserId();

        // Display name update
        $displayName = InputSanitizer::string($this->getPost('display_name', ''));
        if ($displayName !== '') {
            $userModel = new User($this->app->getDatabase());
            $userModel->update($userId, ['display_name' => $displayName]);

            // Refresh user data in session
            $this->auth()->refreshUser();
        }

        // Theme preference
        $theme = $this->getPost('theme', 'light');
        if (in_array($theme, ['light', 'dark', 'auto'])) {
            $prefModel->set($userId, 'theme', $theme);
        }

        // Results per page
        $resultsPerPage = InputSanitizer::positiveInt($this->getPost('results_per_page'), 20);
        if ($resultsPerPage >= 10 && $resultsPerPage <= 100) {
            $prefModel->set($userId, 'results_per_page', (string) $resultsPerPage);
        }

        // Email notifications (for future use)
        $emailNotifications = InputSanitizer::boolean($this->getPost('email_notifications', false));
        $prefModel->set($userId, 'email_notifications', $emailNotifications ? '1' : '0');

        if ($this->isAjax()) {
            return $this->json(['success' => true, 'message' => 'Preferences saved']);
        }

        return $this->redirect('/preferences?saved=1');
    }

    /**
     * Change password
     */
    public function changePassword(): Response
    {
        if ($redirect = $this->requireAuth()) {
            return $redirect;
        }

        $currentPassword = $this->getPost('current_password', '');
        $newPassword = $this->getPost('new_password', '');
        $confirmPassword = $this->getPost('confirm_password', '');

        // Validate
        if (empty($currentPassword) || empty($newPassword)) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'All password fields are required'], 400);
            }
            return $this->redirect('/preferences?error=password_required');
        }

        if ($newPassword !== $confirmPassword) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'New passwords do not match'], 400);
            }
            return $this->redirect('/preferences?error=password_mismatch');
        }

        if (strlen($newPassword) < 8) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Password must be at least 8 characters'], 400);
            }
            return $this->redirect('/preferences?error=password_short');
        }

        $userModel = new User($this->app->getDatabase());
        $user = $userModel->find($this->getUserId());

        // Verify current password
        if (!$userModel->verifyPassword($user, $currentPassword)) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Current password is incorrect'], 400);
            }
            return $this->redirect('/preferences?error=password_wrong');
        }

        // Update password
        $newHash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
        $userModel->update($this->getUserId(), ['password_hash' => $newHash]);

        if ($this->isAjax()) {
            return $this->json(['success' => true, 'message' => 'Password changed successfully']);
        }

        return $this->redirect('/preferences?success=password_changed');
    }
}
