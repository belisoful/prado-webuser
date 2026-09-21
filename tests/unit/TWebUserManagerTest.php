<?php

use Belisoful\Prado\Security\TWebUser;
use Belisoful\Prado\Security\TWebUserManager;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\Exceptions\TInvalidOperationException;

require_once(__DIR__ . '/../test_tools/WebUserTestTools.php');

class TWebUserManagerTest extends PHPUnit\Framework\TestCase
{
	/**
	 * @param array $properties settings to apply before init
	 * @return \TestWebUserManager a manager whose accounts can sign in as soon as they are made
	 */
	private function activeManager(array $properties = []): TestWebUserManager
	{
		return WebUserTestTools::createManager($properties + ['RequireEmailVerification' => false]);
	}

	public function testDefaultsAskForEmailVerificationButNotApproval()
	{
		$manager = WebUserTestTools::createManager();
		$this->assertTrue($manager->getRequireEmailVerification());
		$this->assertFalse($manager->getRequireApproval());
		$this->assertFalse($manager->getAllowDuplicateEmail());
		$this->assertSame('users', $manager->getTableName());
		$this->assertSame('user_tokens', $manager->getTokenTableName());
		$this->assertSame(TWebUserManager::STATUS_PENDING_EMAIL, $manager->getInitialStatus());
	}

	public function testCreateUserStoresTheAccount()
	{
		$manager = WebUserTestTools::createManager();
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com', [
			'DisplayName' => 'Rayelan',
			'Url' => 'https://example.com/rayelan',
			'RegisteredIp' => '203.0.113.7',
		]);

		$this->assertInstanceOf(TWebUser::class, $user);
		$this->assertGreaterThan(0, $user->getID());
		$this->assertSame('rayelan', $user->getName());
		$this->assertSame('rayelan@example.com', $user->getEmail());
		$this->assertSame('Rayelan', $user->getDisplayName());
		$this->assertSame('https://example.com/rayelan', $user->getUrl());
		$this->assertSame('203.0.113.7', $user->getRegisteredIp());
		$this->assertGreaterThan(0, $user->getRegisteredTime());
		$this->assertFalse($user->getIsGuest());
	}

	public function testTheDisplayNameFallsBackToTheUserName()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$this->assertSame('rayelan', $user->getDisplayName());
	}

	public function testThePasswordIsHashedAndNeverStoredAsGiven()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$row = WebUserTestTools::readRow($manager, $user->getID());

		$this->assertNotSame('correct horse', $row['user_pass']);
		$this->assertStringNotContainsString('correct horse', (string) $row['user_pass']);
		$this->assertTrue(password_verify('correct horse', (string) $row['user_pass']));
	}

	public function testCreateUserRejectsAnEmptyNameOrPassword()
	{
		$manager = $this->activeManager();
		$this->assertThrows(TInvalidDataValueException::class, fn () => $manager->createUser('', 'correct horse'));
		$this->assertThrows(TInvalidDataValueException::class, fn () => $manager->createUser('rayelan', ''));
	}

	public function testCreateUserRejectsANameThatIsTaken()
	{
		$manager = $this->activeManager();
		$manager->createUser('rayelan', 'correct horse');

		$this->expectException(TInvalidDataValueException::class);
		$manager->createUser('rayelan', 'another password');
	}

	public function testCreateUserRejectsAnEmailThatIsTaken()
	{
		$manager = $this->activeManager();
		$manager->createUser('rayelan', 'correct horse', 'shared@example.com');

		$this->expectException(TInvalidDataValueException::class);
		$manager->createUser('hobie', 'another password', 'shared@example.com');
	}

	public function testTwoAccountsMayShareAnEmailWhenThatIsAllowed()
	{
		$manager = $this->activeManager(['AllowDuplicateEmail' => true]);
		$manager->createUser('rayelan', 'correct horse', 'shared@example.com');
		$second = $manager->createUser('hobie', 'another password', 'shared@example.com');

		$this->assertGreaterThan(0, $second->getID());
	}

	public function testTheStartingStatusFollowsTheRegistrationSettings()
	{
		$open = WebUserTestTools::createManager(['RequireEmailVerification' => false]);
		$this->assertSame(TWebUserManager::STATUS_ACTIVE, $open->getInitialStatus());

		$approval = WebUserTestTools::createManager(['RequireEmailVerification' => false, 'RequireApproval' => true]);
		$this->assertSame(TWebUserManager::STATUS_PENDING_APPROVAL, $approval->getInitialStatus());

		$verify = WebUserTestTools::createManager(['RequireApproval' => true]);
		$this->assertSame(TWebUserManager::STATUS_PENDING_EMAIL, $verify->getInitialStatus());
	}

	public function testCreatingAnAccountRaisesItsEvent()
	{
		$manager = $this->activeManager();
		$seen = null;
		$manager->attachEventHandler('onUserCreated', function ($sender, $user) use (&$seen) {
			$seen = $user;
		});
		$user = $manager->createUser('rayelan', 'correct horse');

		$this->assertInstanceOf(TWebUser::class, $seen);
		$this->assertSame($user->getID(), $seen->getID());
	}

	public function testCorrectCredentialsSignAnActiveAccountIn()
	{
		$manager = $this->activeManager();
		$manager->createUser('rayelan', 'correct horse');

		$user = $manager->verifyCredentials('rayelan', 'correct horse');
		$this->assertInstanceOf(TWebUser::class, $user);
		$this->assertSame('rayelan', $user->getName());
		$this->assertTrue($manager->validateUser('rayelan', 'correct horse'));
	}

	public function testWrongCredentialsAreRefused()
	{
		$manager = $this->activeManager();
		$manager->createUser('rayelan', 'correct horse');

		$this->assertNull($manager->verifyCredentials('rayelan', 'wrong password'));
		$this->assertNull($manager->verifyCredentials('nobody', 'correct horse'));
		$this->assertFalse($manager->validateUser('rayelan', 'wrong password'));
	}

	/**
	 * The status is what decides, not the password: an account waiting for verification or one
	 * that has been suspended must not sign in even when the password is right.
	 */
	public function testOnlyAnActiveAccountMaySignIn()
	{
		$manager = WebUserTestTools::createManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$this->assertSame(TWebUserManager::STATUS_PENDING_EMAIL, $user->getStatus());
		$this->assertNull($manager->verifyCredentials('rayelan', 'correct horse'));

		foreach ([TWebUserManager::STATUS_PENDING_APPROVAL, TWebUserManager::STATUS_DISABLED, TWebUserManager::STATUS_DELETED] as $status) {
			$manager->createUser('user' . $status, 'correct horse', '', ['Status' => $status]);
			$this->assertNull(
				$manager->verifyCredentials('user' . $status, 'correct horse'),
				"status {$status} cannot sign in"
			);
		}
	}

	public function testAPasswordHashedByAnOlderCostIsUpgradedOnSignIn()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$weak = password_hash('correct horse', PASSWORD_BCRYPT, ['cost' => 4]);
		WebUserTestTools::writeRawPasswordHash($manager, $user->getID(), $weak);

		$this->assertNotNull($manager->verifyCredentials('rayelan', 'correct horse'));

		$stored = (string) WebUserTestTools::readRow($manager, $user->getID())['user_pass'];
		$this->assertNotSame($weak, $stored, 'the old hash was replaced');
		$this->assertTrue(password_verify('correct horse', $stored), 'the replacement still matches the password');
		$this->assertFalse(password_needs_rehash($stored, PASSWORD_DEFAULT));
	}

	public function testAnActivationTokenConfirmsTheAddress()
	{
		$manager = WebUserTestTools::createManager();
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com');
		$token = $manager->issueActivationToken($user);

		$activated = $manager->activateWithToken($token);
		$this->assertInstanceOf(TWebUser::class, $activated);
		$this->assertSame(TWebUserManager::STATUS_ACTIVE, $activated->getStatus());
		$this->assertNotNull($manager->verifyCredentials('rayelan', 'correct horse'));
	}

	public function testActivationLeavesTheAccountWaitingWhenApprovalIsAlsoRequired()
	{
		$manager = WebUserTestTools::createManager(['RequireApproval' => true]);
		$user = $manager->createUser('rayelan', 'correct horse');
		$token = $manager->issueActivationToken($user);

		$activated = $manager->activateWithToken($token);
		$this->assertSame(TWebUserManager::STATUS_PENDING_APPROVAL, $activated->getStatus());
		$this->assertNull($manager->verifyCredentials('rayelan', 'correct horse'));

		$manager->approveUser($activated);
		$this->assertNotNull($manager->verifyCredentials('rayelan', 'correct horse'));
	}

	public function testAnActivationTokenWorksOnlyOnce()
	{
		$manager = WebUserTestTools::createManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$token = $manager->issueActivationToken($user);

		$this->assertNotNull($manager->activateWithToken($token));
		$this->assertNull($manager->activateWithToken($token));
	}

	public function testATokenIsRefusedOnceItHasExpired()
	{
		$manager = WebUserTestTools::createManager(['TokenLifetime' => -10]);
		$user = $manager->createUser('rayelan', 'correct horse');
		$token = $manager->issueActivationToken($user);

		$this->assertNull($manager->activateWithToken($token));
	}

	public function testATokenIsRefusedForAnotherPurpose()
	{
		// A reset link must not be usable as an activation link, or the wrong email gets an
		// account past verification.
		$manager = WebUserTestTools::createManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$reset = $manager->issuePasswordResetToken($user);

		$this->assertNull($manager->activateWithToken($reset));
	}

	public function testAWrongOrMalformedTokenIsRefused()
	{
		$manager = WebUserTestTools::createManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$token = $manager->issueActivationToken($user);
		[$selector] = explode(':', $token, 2);

		$this->assertNull($manager->activateWithToken($selector . ':' . bin2hex(random_bytes(32))));
		$this->assertNull($manager->activateWithToken('not-a-token'));
		$this->assertNull($manager->activateWithToken(''));
		$this->assertNull($manager->activateWithToken(':'));
	}

	public function testOnlyTheHashOfATokenIsStored()
	{
		$manager = WebUserTestTools::createManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$token = $manager->issueActivationToken($user);
		[$selector, $secret] = explode(':', $token, 2);

		$row = $manager->getTestDbConnection()
			->createCommand('SELECT * FROM ' . $manager->getTokenTableName())
			->query()->read();

		$this->assertSame($selector, $row['selector']);
		$this->assertNotSame($secret, $row['token_hash'], 'the secret half is not stored as given');
		$this->assertSame(hash('sha256', $secret), $row['token_hash']);
	}

	public function testAPasswordResetTokenSetsANewPassword()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$token = $manager->issuePasswordResetToken($user);

		$this->assertNotNull($manager->resetPasswordWithToken($token, 'a new password'));
		$this->assertNull($manager->verifyCredentials('rayelan', 'correct horse'));
		$this->assertNotNull($manager->verifyCredentials('rayelan', 'a new password'));
		$this->assertNull($manager->resetPasswordWithToken($token, 'later password'), 'the token was spent');
	}

	public function testChangingAPasswordRevokesEveryToken()
	{
		// A password is changed when it may have been learned, so anything already issued against
		// the old one stops working.
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$cookie = $manager->issueCookieToken($user);
		$reset = $manager->issuePasswordResetToken($user);

		$manager->changePassword($user, 'a new password');

		$this->assertNull($manager->userFromCookieValue($cookie));
		$this->assertNull($manager->resetPasswordWithToken($reset, 'later password'));
		$this->assertNotNull($manager->verifyCredentials('rayelan', 'a new password'));
	}

	public function testChangingAPasswordRejectsAnEmptyOne()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');

		$this->expectException(TInvalidDataValueException::class);
		$manager->changePassword($user, '');
	}

	public function testARememberedBrowserSignsBackIn()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$cookie = $manager->issueCookieToken($user);

		$remembered = $manager->userFromCookieValue($cookie);
		$this->assertInstanceOf(TWebUser::class, $remembered);
		$this->assertSame($user->getID(), $remembered->getID());
	}

	public function testARememberedBrowserIsRefusedOnceTheAccountIsSuspended()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$cookie = $manager->issueCookieToken($user);

		$manager->disableUser($user);
		$this->assertNull($manager->userFromCookieValue($cookie));
	}

	public function testARememberedBrowserCanBeForgotten()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$first = $manager->issueCookieToken($user);
		$second = $manager->issueCookieToken($user);

		$manager->revokeCookieToken($first);
		$this->assertNull($manager->userFromCookieValue($first), 'the browser that was forgotten');
		$this->assertNotNull($manager->userFromCookieValue($second), 'the other browser still works');

		$manager->revokeCookieToken(null, $user->getID());
		$this->assertNull($manager->userFromCookieValue($second), 'every browser was forgotten');
	}

	public function testApprovingDecliningDisablingAndEnablingWriteTheStatus()
	{
		$manager = WebUserTestTools::createManager(['RequireEmailVerification' => false, 'RequireApproval' => true]);
		$user = $manager->createUser('rayelan', 'correct horse');
		$this->assertSame(TWebUserManager::STATUS_PENDING_APPROVAL, $user->getStatus());

		$manager->approveUser($user);
		$this->assertSame(TWebUserManager::STATUS_ACTIVE, $manager->findUserByName('rayelan')->getStatus());

		$manager->disableUser($user);
		$this->assertSame(TWebUserManager::STATUS_DISABLED, $manager->findUserByName('rayelan')->getStatus());

		$manager->enableUser($user);
		$this->assertSame(TWebUserManager::STATUS_ACTIVE, $manager->findUserByName('rayelan')->getStatus());

		$manager->declineUser($user);
		$this->assertSame(TWebUserManager::STATUS_DISABLED, $manager->findUserByName('rayelan')->getStatus());
	}

	public function testEachLifecycleStepRaisesItsEvent()
	{
		$manager = $this->activeManager();
		$raised = [];
		foreach (['onUserApproved', 'onUserDeclined', 'onUserDisabled', 'onUserEnabled', 'onUserDeleted', 'onPasswordChanged'] as $event) {
			$manager->attachEventHandler($event, function () use ($event, &$raised) {
				$raised[] = $event;
			});
		}
		$user = $manager->createUser('rayelan', 'correct horse');
		$manager->approveUser($user);
		$manager->declineUser($user);
		$manager->disableUser($user);
		$manager->enableUser($user);
		$manager->changePassword($user, 'a new password');
		$manager->deleteUser($user);

		$this->assertSame(
			['onUserApproved', 'onUserDeclined', 'onUserDisabled', 'onUserEnabled', 'onPasswordChanged', 'onUserDeleted'],
			$raised
		);
	}

	public function testADeletedAccountKeepsItsNameReserved()
	{
		// The row stays so old posts still have an author, and the name cannot be registered
		// again to inherit that history.
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$manager->deleteUser($user);

		$this->assertSame(TWebUserManager::STATUS_DELETED, $manager->findUserByName('rayelan')->getStatus());
		$this->assertNull($manager->verifyCredentials('rayelan', 'correct horse'));

		$this->expectException(TInvalidDataValueException::class);
		$manager->createUser('rayelan', 'another password');
	}

	public function testPurgingAnAccountRemovesItAndFreesTheName()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$manager->issueCookieToken($user);
		$manager->purgeUser($user);

		$this->assertNull($manager->findUserByName('rayelan'));
		$this->assertSame(0, WebUserTestTools::countTokens($manager));
		$this->assertGreaterThan(0, $manager->createUser('rayelan', 'another password')->getID());
	}

	public function testActingOnAnUnstoredAccountIsRefused()
	{
		$manager = $this->activeManager();
		$stranger = new TWebUser($manager);

		$this->expectException(TInvalidOperationException::class);
		$manager->disableUser($stranger);
	}

	public function testSigningInIsRecorded()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$this->assertSame(0, $user->getLoginTime());

		$manager->recordLogin($user, '203.0.113.7');

		$stored = $manager->findUserByName('rayelan');
		$this->assertGreaterThan(0, $stored->getLoginTime());
		$this->assertGreaterThan(0, $stored->getAccessTime());
		$this->assertSame('203.0.113.7', WebUserTestTools::readRow($manager, $user->getID())['login_ip']);
	}

	public function testRolesAreStoredAndRestored()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse', '', ['Roles' => ['editor', 'moderator']]);

		$restored = $manager->findUserByName('rayelan');
		$this->assertTrue($restored->isInRole('editor'));
		$this->assertTrue($restored->isInRole('moderator'));
		$this->assertFalse($restored->isInRole('administrator'));

		$manager->setUserRoles($user, ['administrator']);
		$this->assertTrue($manager->findUserByName('rayelan')->isInRole('administrator'));
		$this->assertFalse($manager->findUserByName('rayelan')->isInRole('editor'));
	}

	public function testAccountsCanBeFoundByNameIdAndEmail()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com');

		$this->assertSame($user->getID(), $manager->findUserByName('rayelan')->getID());
		$this->assertSame($user->getID(), $manager->findUserById($user->getID())->getID());
		$this->assertSame($user->getID(), $manager->findUserByEmail('rayelan@example.com')->getID());
		$this->assertNull($manager->findUserByName('nobody'));
		$this->assertNull($manager->findUserById(9999));
		$this->assertNull($manager->findUserByEmail('nobody@example.com'));
	}

	public function testTheFrameworkGetUserReadsAnAccount()
	{
		$manager = $this->activeManager();
		$manager->createUser('rayelan', 'correct horse');

		$user = $manager->getUser('rayelan');
		$this->assertInstanceOf(TWebUser::class, $user);
		$this->assertSame('rayelan', $user->getName());

		$guest = $manager->getUser(null);
		$this->assertTrue($guest->getIsGuest());
	}

	public function testExpiredTokensCanBeCleanedUp()
	{
		$manager = WebUserTestTools::createManager(['TokenLifetime' => -10]);
		$user = $manager->createUser('rayelan', 'correct horse');
		$manager->issueActivationToken($user);
		$manager->issuePasswordResetToken($user);
		$this->assertSame(2, WebUserTestTools::countTokens($manager));

		$this->assertSame(2, $manager->purgeExpiredTokens());
		$this->assertSame(0, WebUserTestTools::countTokens($manager));
	}

	public function testCountingAccountsByStatus()
	{
		$manager = WebUserTestTools::createManager();
		$manager->createUser('rayelan', 'correct horse');
		$manager->createUser('hobie', 'correct horse');

		$this->assertSame(2, $manager->countUsersByStatus(TWebUserManager::STATUS_PENDING_EMAIL));
		$this->assertSame(0, $manager->countUsersByStatus(TWebUserManager::STATUS_ACTIVE));
	}

	public function testMissingTablesAreAConfigurationErrorWhenTheyCannotBeCreated()
	{
		$manager = WebUserTestTools::createManager(['AutoCreateTables' => false]);

		$this->expectException(TConfigurationException::class);
		$manager->findUserByName('rayelan');
	}

	public function testTableNamesFreezeOnceInitialized()
	{
		$manager = WebUserTestTools::createManager();

		$this->expectException(TInvalidOperationException::class);
		$manager->setTableName('somewhere_else');
	}

	/**
	 * @param string $exception the exception expected
	 * @param callable $call what should throw it
	 */
	private function assertThrows(string $exception, callable $call): void
	{
		try {
			$call();
			$this->fail("expected {$exception}");
		} catch (\Throwable $thrown) {
			$this->assertInstanceOf($exception, $thrown);
		}
	}
}
