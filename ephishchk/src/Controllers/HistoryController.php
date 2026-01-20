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
        $page = InputSanitizer::positiveInt($this->getQuery('page'), 1);
        $perPage = 20;
        $offset = ($page - 1) * $perPage;

        $orchestrator = new ScanOrchestrator($this->app);
        $scanModel = $orchestrator->getScanModel();

        $scans = $scanModel->getRecent($perPage, $offset);
        $total = $scanModel->count();
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
        $id = InputSanitizer::positiveInt($this->getParam('id'), 0);

        if ($id === 0) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Invalid scan ID'], 400);
            }
            return $this->redirect('/history');
        }

        $orchestrator = new ScanOrchestrator($this->app);
        $deleted = $orchestrator->getScanModel()->delete($id);

        if ($this->isAjax()) {
            return $this->json(['success' => $deleted]);
        }

        return $this->redirect('/history');
    }
}
