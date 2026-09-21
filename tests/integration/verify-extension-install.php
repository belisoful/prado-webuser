<?php

/**
 * Composer-extension integration checks.
 *
 * The unit suite registers the extension's error messages and class map by hand, so it cannot
 * prove that a real `composer require` wires them up. This script runs inside a throwaway
 * consumer project that installed the extension through Composer and asserts the three things
 * `composer.json`'s `extra.prado` section promises:
 *
 * - `error-messages` registers `config/errorMessages.txt`, so the package's codes resolve to text.
 * - `class-map` registers the Prado3 short names, so `TWebUserManager` resolves to its FQN.
 * - `bootstrap` names the module, so `<module id="belisoful/prado-webuser"/>` boots it.
 *
 * Each mode runs in its own process because a Prado application is a per-process singleton.
 *
 *     php verify-extension-install.php <capture|boot> <consumer-dir>
 *
 * Exits non-zero with a message on the first failed check.
 */

use Belisoful\Prado\Security\TWebUser;
use Belisoful\Prado\Security\TWebUserManager;
use Prado\Exceptions\TException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\Prado;
use Prado\TApplication;
use Prado\TApplicationConfiguration;

$mode = $argv[1] ?? '';
$dir = $argv[2] ?? '';
if ($mode === '' || $dir === '' || !is_file($dir . '/vendor/autoload.php')) {
	fwrite(STDERR, "usage: verify-extension-install.php <capture|boot> <consumer-dir>\n");
	exit(2);
}
require $dir . '/vendor/autoload.php';
chdir($dir);

$package = 'belisoful/prado-webuser';
$checks = 0;
$check = function (bool $ok, string $what) use (&$checks): void {
	$checks++;
	if (!$ok) {
		fwrite(STDERR, "FAIL: {$what}\n");
		exit(1);
	}
	fwrite(STDERR, "  ok: {$what}\n");
};

$application = new TApplication($dir . '/protected', false);
$configuration = new TApplicationConfiguration();
$configuration->captureComposerExtensions();

if ($mode === 'capture') {
	$messages = $configuration->getErrorMessages();
	$check(
		count(array_filter($messages, fn ($f) => str_ends_with($f, 'config/errorMessages.txt'))) === 1,
		'extra.prado.error-messages registered the extension message file'
	);

	$map = $configuration->getClassMap();
	$declared = json_decode(
		(string) file_get_contents($dir . '/vendor/' . $package . '/config/classes.json'),
		true,
		512,
		JSON_THROW_ON_ERROR
	);
	$check($map !== [], 'extra.prado.class-map registered a class map');
	foreach ($declared as $short => $fqn) {
		if (($map[$short] ?? null) !== $fqn) {
			$check(false, "class map entry {$short} => {$fqn}");
		}
	}
	$check(true, 'every class-map entry maps to its declared FQN');

	$check(
		$configuration->getComposerExtensionClass($package) === TWebUserManager::class,
		'extra.prado.bootstrap names TWebUserManager'
	);
	// The consumer requires only this extension; the framework has to arrive through it.
	$check(
		is_dir($dir . '/vendor/pradosoft/prado'),
		'pradosoft/prado was installed transitively, without the consumer requiring it'
	);
	$check(class_exists(TApplication::class), 'the transitively-installed framework autoloads');

	foreach ($messages as $file) {
		TException::addMessageFile($file);
	}
	Prado::registerClassMap($map);

	$exception = new TInvalidDataValueException('webuser_name_taken', 'rayelan');
	$check(
		$exception->getMessage() !== 'webuser_name_taken',
		'an extension error code resolves to its message text'
	);
	foreach (array_keys($declared) as $short) {
		Prado::usingClass($short);
		if (!class_exists($short, false) && !interface_exists($short, false)) {
			$check(false, "the Prado3 short name {$short} resolves through the class map");
		}
	}
	$check(true, 'every Prado3 short name resolves through the class map');
} else {
	$configuration->loadFromFile($dir . '/protected/application.xml');
	$application->applyConfiguration($configuration);

	$module = $application->getModule($package);
	$check($module instanceof TWebUserManager, 'the bootstrap module booted under its package id');
	$check($module->getTableName() === 'users', 'the manager stores accounts in the users table');
	$check($module->getInitialStatus() === TWebUserManager::STATUS_PENDING_EMAIL, 'a new account starts unverified');

	// Nothing here touches the database: the factory user proves the module defaulted UserClass
	// to TWebUser and that the framework can build a user from it.
	$guest = $module->getUser(null);
	$check($guest instanceof TWebUser, 'the manager builds users of its own class');
	$check($guest->getIsGuest(), 'a user built with no name is a guest');
	$check(!$guest->getCanLogin(), 'a guest may not sign in');
}

fwrite(STDERR, "{$checks} checks passed ({$mode})\n");
