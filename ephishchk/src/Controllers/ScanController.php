<?php

declare(strict_types=1);

namespace Ephishchk\Controllers;

use Ephishchk\Core\Response;
use Ephishchk\Services\ScanOrchestrator;
use Ephishchk\Security\InputSanitizer;

/**
 * Scan Controller
 */
class ScanController extends BaseController
{
    /**
     * Display scan form (home page)
     */
    public function index(): Response
    {
        return $this->render('scan/index', [
            'title' => 'Email Phishing Checker',
        ]);
    }

    /**
     * Perform quick check (domain/email)
     */
    public function quickCheck(): Response
    {
        $input = InputSanitizer::string($this->getPost('input', ''));

        if (empty($input)) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Please enter an email address or domain'], 400);
            }
            return $this->render('scan/index', [
                'title' => 'Email Phishing Checker',
                'error' => 'Please enter an email address or domain',
            ]);
        }

        $orchestrator = new ScanOrchestrator($this->app);
        $result = $orchestrator->quickCheck($input, $this->request->getClientIp());

        if (isset($result['error'])) {
            if ($this->isAjax()) {
                return $this->json(['error' => $result['error']], 400);
            }
            return $this->render('scan/index', [
                'title' => 'Email Phishing Checker',
                'error' => $result['error'],
                'input' => $input,
            ]);
        }

        if ($this->isAjax()) {
            return $this->json($result);
        }

        return $this->redirect('/scan/' . $result['id']);
    }

    /**
     * Perform full email analysis
     */
    public function fullAnalysis(): Response
    {
        $rawEmail = InputSanitizer::rawEmail($this->getPost('email_content', ''));

        if (empty($rawEmail)) {
            if ($this->isAjax()) {
                return $this->json(['error' => 'Please paste the raw email content'], 400);
            }
            return $this->render('scan/index', [
                'title' => 'Email Phishing Checker',
                'error' => 'Please paste the raw email content',
                'activeTab' => 'full',
            ]);
        }

        $orchestrator = new ScanOrchestrator($this->app);
        $result = $orchestrator->fullAnalysis($rawEmail, $this->request->getClientIp());

        if (isset($result['error'])) {
            if ($this->isAjax()) {
                return $this->json(['error' => $result['error']], 400);
            }
            return $this->render('scan/index', [
                'title' => 'Email Phishing Checker',
                'error' => $result['error'],
                'activeTab' => 'full',
            ]);
        }

        if ($this->isAjax()) {
            return $this->json($result);
        }

        return $this->redirect('/scan/' . $result['id']);
    }

    /**
     * Get scan status (for polling)
     */
    public function status(): Response
    {
        $id = InputSanitizer::positiveInt($this->getParam('id'), 0);

        if ($id === 0) {
            return $this->json(['error' => 'Invalid scan ID'], 400);
        }

        $orchestrator = new ScanOrchestrator($this->app);
        $scan = $orchestrator->getScanModel()->find($id);

        if (!$scan) {
            return $this->json(['error' => 'Scan not found'], 404);
        }

        return $this->json([
            'id' => $scan['id'],
            'status' => $scan['status'],
            'risk_score' => $scan['risk_score'],
        ]);
    }

    /**
     * Show scan results
     */
    public function show(): Response
    {
        $id = InputSanitizer::positiveInt($this->getParam('id'), 0);

        if ($id === 0) {
            return Response::notFound('Invalid scan ID');
        }

        $orchestrator = new ScanOrchestrator($this->app);
        $scan = $orchestrator->getScanModel()->findWithResults($id);

        if (!$scan) {
            return Response::notFound('Scan not found');
        }

        // Group results by check type
        $resultsByType = [];
        foreach ($scan['results'] as $result) {
            $resultsByType[$result['check_type']] = $result;
        }

        return $this->render('scan/show', [
            'title' => 'Scan Results',
            'scan' => $scan,
            'resultsByType' => $resultsByType,
        ]);
    }
}
