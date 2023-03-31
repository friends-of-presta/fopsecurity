<?php
/**
 * Copyright (c) Since 2020 Friends of Presta
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Academic Free License (AFL 3.0)
 * that is bundled with this package in the file docs/licenses/LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * https://opensource.org/licenses/afl-3.0.php
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to infos@friendsofpresta.org so we can send you a copy immediately.
 *
 * @author    Friends of Presta <infos@friendsofpresta.org>
 * @copyright since 2020 Friends of Presta
 * @license   https://opensource.org/licenses/AFL-3.0  Academic Free License ("AFL") v. 3.0
 */
include_once __DIR__ . '/../../classes/WAFApache.php';

class AdminFopSecurityConfigurationController extends ModuleAdminController
{
    public function __construct()
    {
        $this->bootstrap = true;
        $this->className = 'Configuration';
        $this->table = 'configuration';

        parent::__construct();

        $this->fields_options = [
            'apachewaf' => [
                'title' => $this->l('Apache WAF'),
                // 'description' => $this->l('Generate .htaccess rules to block malicous calls'),
                'info' => $this->l('Generate .htaccess rules to block malicous calls'),
                'icon' => 'icon-cogs',
                'fields' => [
                    'FOPSECURITY_BLOCK_DIRECTORYTRAVERSAL' => [
                        'type' => 'bool',
                        'title' => $this->l('Block directory traversal'),
                        'cast' => 'boolval',
                    ],
                    'FOPSECURITY_BLOCK_PHPUNITFOLDER' => [
                        'type' => 'bool',
                        'title' => $this->l('Block phpunit folder'),
                        'desc' => $this->l('Acces to phpunit folders in modules is forbidden.') . ' <a href="https://build.prestashop-project.org/news/2020/critical-security-vulnerability-in-prestashop-modules/">source</a>',
                        'cast' => 'boolval',
                    ],
                    'FOPSECURITY_BLOCK_KNOWNMALWARES' => [
                        'type' => 'bool',
                        'title' => $this->l('Block known malwares'),
                        'desc' => $this->l('XsamXadoo, ...'),
                        'cast' => 'boolval',
                    ],
                ],
                'submit' => [
                    'title' => $this->l('Save'),
                ],
            ],
        ];
    }

    public function postProcess()
    {
        parent::postProcess();

        $wafApache = new WAFApache();
        $wafApache->writeHtaccessSection();
    }
}
