<?php

declare(strict_types=1);

namespace Ephishchk\Controllers;

use Ephishchk\Core\Response;
use Ephishchk\Services\ScanOrchestrator;
use Ephishchk\Security\InputSanitizer;

/**
 * Settings Controller
 */
class SettingsController extends BaseController
{
    /**
     * Display settings page
     */
    public function index(): Response
    {
        $orchestrator = new ScanOrchestrator($this->app);
        $settings = $orchestrator->getSettingModel()->all();

        // Get VirusTotal status
        $vtStatus = null;
        $vtClient = $orchestrator->getVirusTotalClient();
        if ($vtClient && $vtClient->isConfigured()) {
            $vtStatus = $vtClient->getRateLimitStatus();
        }

        return $this->render('settings/index', [
            'title' => 'Settings',
            'settings' => $settings,
            'vtStatus' => $vtStatus,
            'vtConfigured' => $vtClient && $vtClient->isConfigured(),
        ]);
    }

    /**
     * Save settings
     */
    public function save(): Response
    {
        $orchestrator = new ScanOrchestrator($this->app);
        $settingModel = $orchestrator->getSettingModel();

        // VirusTotal API Key
        $vtApiKey = InputSanitizer::string($this->getPost('virustotal_api_key', ''));
        if (!empty($vtApiKey)) {
            $settingModel->set('virustotal_api_key', $vtApiKey, 'string', true);
        }

        // VirusTotal Tier
        $vtTier = $this->getPost('virustotal_tier', 'free');
        if (in_array($vtTier, ['free', 'premium'])) {
            $settingModel->set('virustotal_tier', $vtTier);
        }

        // Scan retention days
        $retentionDays = InputSanitizer::positiveInt($this->getPost('scan_retention_days'), 30);
        $settingModel->set('scan_retention_days', $retentionDays, 'integer');

        // Max links per scan
        $maxLinks = InputSanitizer::positiveInt($this->getPost('max_links_per_scan'), 50);
        $settingModel->set('max_links_per_scan', $maxLinks, 'integer');

        // Enable/disable toggles
        $settingModel->set('enable_vt_file_scan', InputSanitizer::boolean($this->getPost('enable_vt_file_scan', false)), 'boolean');
        $settingModel->set('enable_vt_url_scan', InputSanitizer::boolean($this->getPost('enable_vt_url_scan', false)), 'boolean');

        if ($this->isAjax()) {
            return $this->json(['success' => true, 'message' => 'Settings saved']);
        }

        return $this->redirect('/settings?saved=1');
    }

    /**
     * Test VirusTotal connection
     */
    public function testVirusTotal(): Response
    {
        $orchestrator = new ScanOrchestrator($this->app);
        $vtClient = $orchestrator->getVirusTotalClient();

        if (!$vtClient || !$vtClient->isConfigured()) {
            return $this->json([
                'success' => false,
                'error' => 'VirusTotal API key not configured',
            ]);
        }

        $result = $vtClient->testConnection();

        return $this->json($result);
    }
}
