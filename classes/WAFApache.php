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
class WAFApache
{
    protected $htaccessRules = '';

    /**
     * Generate WAF rules in Apache mod_rewrite
     *
     * @return void
     */
    public function generateWafRules(): void
    {
        // admin dir
        $admin_dir = basename(_PS_ADMIN_DIR_);

        if (Configuration::get('FOPSECURITY_BLOCK_DIRECTORYTRAVERSAL')) {
            $this->htaccessRules .= 'RewriteCond %{QUERY_STRING} \.\./ [NC]' . "\n";
            $this->htaccessRules .= 'RewriteCond %{REQUEST_URI} !^' . preg_quote($admin_dir) . '/ [NC]' . "\n";
            $this->htaccessRules .= 'RewriteRule .* - [F,L]' . "\n\n";
        }
        if (Configuration::get('FOPSECURITY_BLOCK_PHPUNITFOLDER')) {
            $this->htaccessRules .= 'RewriteRule ^modules/.*phpunit - [F,L]' . "\n\n";
        }
        if (Configuration::get('FOPSECURITY_BLOCK_KNOWNMALWARES')) {
            $this->htaccessRules .= 'RewriteCond %{REQUEST_URI} XsamXadoo [NC,OR]' . "\n";
            $this->htaccessRules .= 'RewriteCond %{REQUEST_URI} Xsam_Xadoo [NC,OR]' . "\n";
            $this->htaccessRules .= 'RewriteRule .* - [F,L]' . "\n\n";
        }
    }

    /**
     * Write fop security section in .htaccess at the begening of the file or in already present section
     *
     * @return bool
     */
    public function writeHtaccessSection(): bool
    {
        // apachewaf
        $regExpForSection = '/^(.*)# --fops-start--.*# --fops-end--[^\n]*[\n]*(.*)$/s';

        // Define the .htaccess file path
        $htaccessFilePath = _PS_ROOT_DIR_ . '/.htaccess';

        $this->generateWafRules();

        $htaccessSection = '# --fops-start-- FoP Security rules -- Do not remove this comment --' . "\n";
        $htaccessSection .= 'RewriteEngine on' . "\n";

        $htaccessSection .= $this->htaccessRules;
        $htaccessSection .= "\n" . '# --fops-end-- FoP Security rules -- Do not remove this comment --' . "\n\n";

        if (file_exists($htaccessFilePath) && is_writable($htaccessFilePath)) {
            // Read the current .htaccess file contents
            $htaccessFileContent = file_get_contents($htaccessFilePath);

            if (preg_match($regExpForSection, $htaccessFileContent)) {
                // Replace the section by new rules
                $htaccessFileContent = preg_replace($regExpForSection, '$1' . $htaccessSection . '$2', $htaccessFileContent, 1);
            } else {
                // Add the block of rules at the begening of the file
                $htaccessFileContent = $htaccessSection . $htaccessFileContent;
            }

            // Write the updated .htaccess file contents
            return (bool) file_put_contents($htaccessFilePath, $htaccessFileContent);
        } else {
            return false;
        }
    }
}
