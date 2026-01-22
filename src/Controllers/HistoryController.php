<?php

declare(strict_types=1);

namespace Ephishchk\Controllers;

use Ephishchk\Core\Response;
use Ephishchk\Services\ScanOrchestrator;
use Ephishchk\Security\InputSanitizer;

/**
 * History Controller
 */
class HistoryController extends BaseController
{
    /**
     * List scan history
     */
    public function index(): Response
    {
        // Require authentication
        if ($redirect = $this->requireAuth()) {
            return $redirect;
        }

        $page = InputSanitizer::positiveInt($this->getQuery('page'), 1);
        $perPage = 20;
        $offset = ($page - 1) * $perPage;

        $orchestrator = new ScanOrchestrator($this->app);
        $scanModel = $orchestrator->getScanModel();

        $userId = $this->getUserId();
        $scans = $scanModel->getRecentByUser($userId, $perPage, $offset);
        $total = $scanModel->countByUser($userId);
        $totalPages = (int) ceil($total / $perPage);

        return $this->render('history/index', [
            'title' => 'Scan History',
            'scans' => $scans,
            'page' => $page,
            'totalPages' => $totalPages,
            'total' => $total,
        ]);
    }

    /**
     * Delete a scan
     */
    public function delete(): Response
    {
        // Require authentication
        if ($redirect = $this->requireAuth()) {
            return $redirect;
        }

        $id = InputSanitizer::positiveInt($this->getParam('id'), 0);

        if ($id === 0) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Invalid scan ID'], 400);
            }
            return $this->redirect('/history');
        }

        $orchestrator = new ScanOrchestrator($this->app);
        $scanModel = $orchestrator->getScanModel();

        // Check ownership before deleting
        $scan = $scanModel->findForUser($id, $this->getUserId());
        $deleted = false;

        if ($scan) {
            $deleted = $scanModel->delete($id);
        }

        if ($this->isAjax()) {
            return $this->json(['success' => $deleted]);
        }

        return $this->redirect('/history');
    }
}
