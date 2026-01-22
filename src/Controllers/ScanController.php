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
                return $this->json(['error' => 'Please enter an email address'], 400);
            }
            return $this->render('scan/index', [
                'title' => 'Email Phishing Checker',
                'error' => 'Please enter an email address',
            ]);
        }

        $orchestrator = new ScanOrchestrator($this->app);
        $result = $orchestrator->quickCheck($input, $this->request->getClientIp(), $this->getUserId());

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
        $rawEmail = '';
        $inputMethod = $this->getPost('input_method', 'paste');

        // Check for file upload first
        if ($inputMethod === 'upload' && isset($_FILES['eml_file']) && $_FILES['eml_file']['error'] === UPLOAD_ERR_OK) {
            $rawEmail = $this->handleEmlUpload($_FILES['eml_file']);
            if ($rawEmail === null) {
                $error = 'Failed to read uploaded file. Please ensure it is a valid .eml file.';
                if ($this->isAjax()) {
                    return $this->json(['error' => $error], 400);
                }
                return $this->render('scan/index', [
                    'title' => 'Email Phishing Checker',
                    'error' => $error,
                    'activeTab' => 'full',
                ]);
            }
        } else {
            // Fall back to pasted content
            $rawEmail = InputSanitizer::rawEmail($this->getPost('email_content', ''));
        }

        if (empty($rawEmail)) {
            $error = $inputMethod === 'upload'
                ? 'Please upload an .eml file'
                : 'Please paste the raw email content';
            if ($this->isAjax()) {
                return $this->json(['error' => $error], 400);
            }
            return $this->render('scan/index', [
                'title' => 'Email Phishing Checker',
                'error' => $error,
                'activeTab' => 'full',
            ]);
        }

        $orchestrator = new ScanOrchestrator($this->app);
        $result = $orchestrator->fullAnalysis($rawEmail, $this->request->getClientIp(), $this->getUserId());

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
     * Handle .eml file upload
     */
    private function handleEmlUpload(array $file): ?string
    {
        // Validate file size (10MB max)
        $maxSize = 10 * 1024 * 1024;
        if ($file['size'] > $maxSize) {
            return null;
        }

        // Validate file extension
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, ['eml', 'msg'])) {
            return null;
        }

        // Validate MIME type (be lenient as some .eml files report different types)
        $allowedTypes = [
            'message/rfc822',
            'text/plain',
            'application/octet-stream',
            'application/vnd.ms-outlook',
        ];
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);

        // Read file content
        $content = file_get_contents($file['tmp_name']);
        if ($content === false) {
            return null;
        }

        return $content;
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
        $scanModel = $orchestrator->getScanModel();
        $scan = $scanModel->find($id);

        if (!$scan) {
            return $this->json(['error' => 'Scan not found'], 404);
        }

        // Allow access if: scan has no user_id (anonymous) OR user owns the scan
        $scanUserId = $scan['user_id'] ?? null;
        $currentUserId = $this->getUserId();

        if ($scanUserId !== null && $scanUserId !== $currentUserId) {
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
        $scanModel = $orchestrator->getScanModel();
        $scan = $scanModel->findWithResults($id);

        if (!$scan) {
            return Response::notFound('Scan not found');
        }

        // Allow access if: scan has no user_id (anonymous) OR user owns the scan
        $scanUserId = $scan['user_id'] ?? null;
        $currentUserId = $this->getUserId();

        if ($scanUserId !== null && $scanUserId !== $currentUserId) {
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
