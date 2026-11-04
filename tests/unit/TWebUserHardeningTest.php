<?php

use Belisoful\Prado\Security\TWebUser;
use Belisoful\Prado\Security\TWebUserManager;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\Exceptions\TInvalidOperationException;
use Prado\Security\TAuthManager;
use Prado\Web\THttpCookie;

require_once(__DIR__ . '/../test_tools/WebUserTestTools.php');

/**
 * Sessions that end when the account changes, sign-in and sign-out through the auth manager,
 * requests racing each other, names and emails without case, and the status an account may be
 * moved from.
 */
class TWebUserHardeningTest extends PHPUnit\Framework\TestCase
{
	private function activeManager(array $properties = [], ?TestWebUserManager $manager = null): TestWebUserManager
	{
		return WebUserTestTools::createManager($properties + ['RequireEmailVerification' => false], $manager);
	}

	/**
	 * @return \Belisoful\Prado\Security\TWebUser the user as the next request reads it from the session
	 */
	private function nextRequest(TWebUserManager $manager, TWebUser $user): TWebUser
	{
		return (new TWebUser($manager))->loadFromString($user->saveToString());
	}

	// ── Sessions ─────────────────────────────────────────────────────────────

	public function testASessionEndsWhenTheAccountIsSuspendedDeletedOrPurged()
	{
		$manager = $this->activeManager();
		foreach (['disableUser', 'deleteUser', 'purgeUser'] as $i => $action) {
			$user = $manager->createUser('user' . $i, 'correct horse');
			$this->assertFalse($this->nextRequest($manager, $user)->getIsGuest(), "{$action}: signed in before");

			$manager->{$action}($user);
			$restored = $this->nextRequest($manager, $user);
			$this->assertTrue($restored->getIsGuest(), "{$action}: a guest after");
			$this->assertSame(0, $restored->getID());
			$this->assertSame([], $restored->getRoles());
		}
	}

	public function testASessionEndsWhenThePasswordChangesElsewhere()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$session = $user->saveToString();

		$manager->changePassword($manager->findUserByName('rayelan'), 'a new password');

		$this->assertTrue((new TWebUser($manager))->loadFromString($session)->getIsGuest());
	}

	public function testASessionSavedWithoutAPasswordStampIsSignedOut()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$user->setPasswordStamp('');

		$this->assertTrue($this->nextRequest($manager, $user)->getIsGuest());
	}

	public function testASessionPicksUpChangesMadeToTheAccount()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse', '', ['Roles' => ['editor']]);
		$session = $user->saveToString();

		$manager->setUserRoles($manager->findUserByName('rayelan'), []);
		$manager->updateProfile($manager->findUserByName('rayelan'), ['DisplayName' => 'Ray']);

		$restored = (new TWebUser($manager))->loadFromString($session);
		$this->assertFalse($restored->getIsGuest());
		$this->assertSame([], $restored->getRoles());
		$this->assertSame('Ray', $restored->getDisplayName());
	}

	public function testRevalidationCanBeTurnedOff()
	{
		$manager = $this->activeManager(['RevalidateSessions' => false]);
		$this->assertFalse($manager->getRevalidateSessions());
		$user = $manager->createUser('rayelan', 'correct horse');
		$manager->disableUser($user);

		$this->assertFalse($this->nextRequest($manager, $user)->getIsGuest());
	}

	public function testAGuestSessionStaysAGuest()
	{
		$manager = $this->activeManager();
		$guest = new TWebUser($manager);

		$this->assertTrue($guest->loadFromString('')->getIsGuest());
		$this->assertFalse($manager->revalidateUser($guest));
	}

	public function testAccessTimeIsWrittenWhenItHasGrownStale()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$this->assertSame(0, $user->getAccessTime());

		$restored = $this->nextRequest($manager, $user);
		$seen = $restored->getAccessTime();
		$this->assertGreaterThan(0, $seen);
		$this->assertSame($seen, (int) WebUserTestTools::readRow($manager, $user->getID())['access_time']);

		// Within the resolution nothing is written; the row, not the session, says when.
		$recent = time() - 10;
		$command = $manager->getTestDbConnection()->createCommand('UPDATE ' . $manager->getTableName() . ' SET access_time = :recent WHERE id = :id');
		$command->bindValue(':recent', $recent);
		$command->bindValue(':id', $user->getID());
		$command->execute();
		$manager->revalidateUser($restored);
		$this->assertSame($recent, (int) WebUserTestTools::readRow($manager, $user->getID())['access_time']);
		$this->assertSame($recent, $restored->getAccessTime());
	}

	public function testARememberedBrowserCountsAsAccess()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$this->assertSame(0, (int) WebUserTestTools::readRow($manager, $user->getID())['access_time']);

		$this->assertNotNull($manager->userFromCookieValue($manager->issueCookieToken($user)));
		$this->assertGreaterThan(0, (int) WebUserTestTools::readRow($manager, $user->getID())['access_time']);
	}

	// ── The auth manager ─────────────────────────────────────────────────────

	/**
	 * @return array{\Prado\TApplication, \TestWebUserManager, \Prado\Security\TAuthManager}
	 */
	private function application(): array
	{
		$application = WebUserTestTools::createApplication();
		$manager = $this->activeManager();
		$application->setModule('users', $manager);
		// The auth manager only writes the session outside the CLI; this one writes to an array.
		$auth = new class () extends TAuthManager {
			public array $session = [];

			protected function getCanPersistSession()
			{
				return true;
			}

			protected function requireSession()
			{
				return new class ($this->session) {
					public function __construct(private array &$items)
					{
					}

					public function add($key, $value): void
					{
						$this->items[$key] = $value;
					}

					public function itemAt($key)
					{
						return $this->items[$key] ?? null;
					}

					public function regenerate($deleteOld = false): string
					{
						return '';
					}
				};
			}
		};
		$auth->setUserManager($manager);
		$application->setModule('auth', $auth);
		$auth->init(null);

		return [$application, $manager, $auth];
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState(false)]
	public function testTheManagerListensToItsAuthManagerOnce()
	{
		[$application, $manager, $auth] = $this->application();
		$other = new TAuthManager();
		$other->setUserManager(new \Prado\Security\TUserManager());
		$application->setModule('otherAuth', $other);

		$manager->bindAuthManagers();
		$manager->bindAuthManagers();
		$application->onInitComplete();

		$this->assertCount(1, $auth->getEventHandlers('OnLogin'));
		$this->assertCount(1, $auth->getEventHandlers('OnLogout'));
		$this->assertCount(0, $other->getEventHandlers('OnLogout'));
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState(false)]
	public function testSigningOutRevokesTheBrowsersRememberMeToken()
	{
		[$application, $manager, $auth] = $this->application();
		$user = $manager->createUser('rayelan', 'correct horse');
		$token = $manager->issueCookieToken($user);
		$kept = $manager->issueCookieToken($user);
		$signed = $application->getSecurityManager()->hashCookieData($token);
		$application->getRequest()->getCookies()->add(new THttpCookie($auth->getUserKey(), $signed));
		$manager->bindAuthManagers();

		$auth->onLogout($user);

		$this->assertNull($manager->userFromCookieValue($token), 'the browser that signed out');
		$this->assertNotNull($manager->userFromCookieValue($kept), 'another browser');
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState(false)]
	public function testAnUnsignedOrMissingCookieRevokesNothing()
	{
		[$application, $manager, $auth] = $this->application();
		$user = $manager->createUser('rayelan', 'correct horse');
		$token = $manager->issueCookieToken($user);

		$manager->handleLogout($auth, $user);
		$application->getRequest()->getCookies()->add(new THttpCookie($auth->getUserKey(), $token));
		$manager->handleLogout($auth, $user);

		$this->assertNotNull($manager->userFromCookieValue($token));
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState(false)]
	public function testSigningInIsRecordedThroughTheAuthManager()
	{
		[, $manager, $auth] = $this->application();
		$user = $manager->createUser('rayelan', 'correct horse');
		$manager->bindAuthManagers();

		$auth->onLogin($user);
		$auth->onLogin(new TWebUser($manager));

		$row = WebUserTestTools::readRow($manager, $user->getID());
		$this->assertGreaterThan(0, (int) $row['login_time']);
		$this->assertSame('127.0.0.1', $row['login_ip']);
	}

	#[RunInSeparateProcess]
	#[PreserveGlobalState(false)]
	public function testChangingYourOwnPasswordKeepsYourSession()
	{
		[$application, $manager, $auth] = $this->application();
		$user = $manager->createUser('rayelan', 'correct horse');
		$elsewhere = $user->saveToString();
		$application->setUser($user);

		$manager->changePassword($user, 'a new password');

		$saved = $auth->session[$auth->getUserKey()] ?? null;
		$this->assertIsString($saved, 'the session was written again');
		$this->assertFalse((new TWebUser($manager))->loadFromString($saved)->getIsGuest(), 'this session goes on');
		$this->assertTrue((new TWebUser($manager))->loadFromString($elsewhere)->getIsGuest(), 'another session ends');
	}

	// ── Timing ───────────────────────────────────────────────────────────────

	public function testAnUnknownNameCostsAPasswordHash()
	{
		$manager = $this->activeManager([], new class () extends TestWebUserManager {
			public int $hashes = 0;

			protected function hashPassword(#[\SensitiveParameter] string $password): string
			{
				$this->hashes++;

				return parent::hashPassword($password);
			}
		});

		$this->assertNull($manager->verifyCredentials('nobody', 'a guess'));
		$this->assertSame(1, $manager->hashes);
	}

	// ── Names and emails ─────────────────────────────────────────────────────

	public function testNamesAndEmailsAreTakenWithoutRegardToCase()
	{
		$manager = $this->activeManager();
		$manager->createUser('Rayelan', 'correct horse', 'Rayelan@Example.com');

		try {
			$manager->createUser('rayelan', 'another');
			$this->fail('a name differing only in case is taken');
		} catch (TInvalidDataValueException $e) {
			$this->assertSame('webuser_name_taken', $e->getErrorCode());
		}
		try {
			$manager->createUser('hobie', 'another', 'rayelan@example.COM');
			$this->fail('an email differing only in case is taken');
		} catch (TInvalidDataValueException $e) {
			$this->assertSame('webuser_email_taken', $e->getErrorCode());
		}
	}

	public function testNamesAndEmailsAreFoundWithoutRegardToCaseOrSpaces()
	{
		$manager = $this->activeManager();
		$manager->createUser('Rayelan', 'correct horse', ' Rayelan@Example.com ');

		$this->assertSame('Rayelan', $manager->verifyCredentials(' rAYELAN ', 'correct horse')?->getName());
		$this->assertSame('Rayelan', $manager->findUserByName('RAYELAN')?->getName());
		$this->assertSame('Rayelan@Example.com', $manager->findUserByEmail('rayelan@example.com ')?->getEmail());
		$this->assertNull($manager->findUserByEmail(''));
	}

	public function testAnEmailMustBeAnAddress()
	{
		$manager = $this->activeManager();
		try {
			$manager->createUser('rayelan', 'correct horse', 'not an address');
			$this->fail('an address is required');
		} catch (TInvalidDataValueException $e) {
			$this->assertSame('webuser_email_invalid', $e->getErrorCode());
		}
		$user = $manager->createUser('rayelan', 'correct horse', 'ränd@example.com');

		$this->expectException(TInvalidDataValueException::class);
		$this->expectExceptionMessage("'nope@' is not an email address.");
		$manager->updateProfile($user, ['Email' => 'nope@']);
	}

	public function testRegistrationsRacingForANameLetTheFirstWin()
	{
		// The check before the insert misses the other registration, as a concurrent one would.
		$manager = $this->activeManager([], new class () extends TestWebUserManager {
			public bool $blind = false;

			public function findUserByName(string $username): ?TWebUser
			{
				return $this->blind ? null : parent::findUserByName($username);
			}
		});
		$manager->createUser('rayelan', 'correct horse');
		$manager->blind = true;

		try {
			$manager->createUser('RAYELAN', 'another');
			$this->fail('the second registration is refused');
		} catch (TInvalidDataValueException $e) {
			$this->assertSame('webuser_name_taken', $e->getErrorCode());
		}
		$manager->blind = false;
		$this->assertSame(1, $manager->countUsers());
	}

	public function testRegistrationsRacingForAnEmailLetTheFirstWin()
	{
		$manager = $this->activeManager([], new class () extends TestWebUserManager {
			public bool $blind = false;

			public function findUserByEmail(string $email): ?TWebUser
			{
				return $this->blind ? null : parent::findUserByEmail($email);
			}
		});
		$first = $manager->createUser('rayelan', 'correct horse', 'shared@example.com');
		$manager->blind = true;

		try {
			$manager->createUser('hobie', 'another', 'SHARED@example.com');
			$this->fail('the second registration is refused');
		} catch (TInvalidDataValueException $e) {
			$this->assertSame('webuser_email_taken', $e->getErrorCode());
		}
		$manager->blind = false;
		$this->assertSame(1, $manager->countUsers());
		$this->assertSame($first->getID(), $manager->findUserByEmail('shared@example.com')->getID());
	}

	public function testSearchFoldsThePatternAsTheDatabaseFoldsTheColumn()
	{
		$manager = $this->activeManager();
		$manager->createUser('Rayelan', 'correct horse', 'Ray@Example.com');

		$this->assertCount(1, $manager->searchUsers('RAY@EXAMPLE'));
		$this->assertSame(1, $manager->countUsers('rayELAN'));
	}

	// ── Tokens and codes ─────────────────────────────────────────────────────

	public function testAnEmptyNewPasswordLeavesTheResetLinkWorking()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$token = $manager->issuePasswordResetToken($user);

		try {
			$manager->resetPasswordWithToken($token, '');
			$this->fail('an empty password is refused');
		} catch (TInvalidDataValueException $e) {
			$this->assertSame('webuser_password_required', $e->getErrorCode());
		}

		$this->assertNotNull($manager->resetPasswordWithToken($token, 'a new password'));
	}

	public function testATokenSpentByAnotherRequestMeanwhileIsRefused()
	{
		// Another request deletes the token between this one reading and deleting it.
		$manager = $this->activeManager([], new class () extends TestWebUserManager {
			protected function readToken(string $token, string $purpose): ?array
			{
				$row = parent::readToken($token, $purpose);
				if ($row !== null) {
					$this->getTestDbConnection()->createCommand('DELETE FROM ' . $this->getTokenTableName())->execute();
				}

				return $row;
			}
		});
		$user = $manager->createUser('rayelan', 'correct horse');

		$this->assertNull($manager->resetPasswordWithToken($manager->issuePasswordResetToken($user), 'a new password'));
		$this->assertNotNull($manager->verifyCredentials('rayelan', 'correct horse'), 'the password is unchanged');
	}

	public function testGuessesAreCountedBeforeTheyAreJudged()
	{
		// Guesses sent together have each recorded themselves before any is judged.
		$manager = WebUserTestTools::createManager(['RequireEmailVerification' => true]);
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com');
		$code = $manager->issueActivationCode($user);
		$command = $manager->getTestDbConnection()->createCommand(
			'INSERT INTO ' . $manager->getTokenTableName() . ' (user_id, purpose, selector, token_hash, expires_time, created_time)'
			. " VALUES (:user, 'code_failure', :selector, '', :expires, 0)"
		);
		for ($i = 0; $i < TWebUserManager::CODE_ATTEMPTS; $i++) {
			$command->bindValue(':user', $user->getID());
			$command->bindValue(':selector', 'other' . $i);
			$command->bindValue(':expires', time() + 600);
			$command->execute();
		}

		$this->assertFalse($manager->activateWithCode($user, $code));
		$this->assertSame(TWebUserManager::STATUS_PENDING_EMAIL, $manager->findUserByName('rayelan')->getStatus());
	}

	public function testACodeSpentByAnotherRequestMeanwhileIsRefused()
	{
		$manager = WebUserTestTools::createManager(['RequireEmailVerification' => true], new class () extends TestWebUserManager {
			public int $activated = 0;

			protected function readTokenRows(int $userId, string $purpose): array
			{
				$rows = parent::readTokenRows($userId, $purpose);
				if ($purpose === self::TOKEN_ACTIVATION_CODE && $rows !== []) {
					$this->revokeTokens($userId, self::TOKEN_ACTIVATION_CODE);
				}

				return $rows;
			}

			public function onUserActivated(TWebUser $user): void
			{
				$this->activated++;
			}
		});
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com');

		$this->assertFalse($manager->activateWithCode($user, $manager->issueActivationCode($user)));
		$this->assertSame(0, $manager->activated);
	}

	public function testActivationOnlyMovesAnAccountStillWaitingOnItsAddress()
	{
		$manager = WebUserTestTools::createManager(['RequireEmailVerification' => true]);
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com');
		$token = $manager->issueActivationToken($user);
		$code = $manager->issueActivationCode($user);
		// Suspended between the user being read and the token being used.
		$command = $manager->getTestDbConnection()->createCommand('UPDATE ' . $manager->getTableName() . ' SET status = 4');
		$command->execute();

		$this->assertNull($manager->activateWithToken($token));
		$this->assertFalse($manager->activateWithCode($user, $code));
		$this->assertSame(TWebUserManager::STATUS_DISABLED, $manager->findUserByName('rayelan')->getStatus());
	}

	// ── Status moves ─────────────────────────────────────────────────────────

	public function testEachStatusMoveIsRefusedFromTheWrongStatus()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$refused = [
			'approveUser' => 'webuser_approve_status',
			'declineUser' => 'webuser_decline_status',
			'enableUser' => 'webuser_enable_status',
		];
		foreach ($refused as $action => $errorCode) {
			try {
				$manager->{$action}($user);
				$this->fail("{$action} of an active account is refused");
			} catch (TInvalidOperationException $e) {
				$this->assertSame($errorCode, $e->getErrorCode());
			}
		}
		$this->assertSame(TWebUserManager::STATUS_ACTIVE, $manager->findUserByName('rayelan')->getStatus());

		$manager->deleteUser($user);
		try {
			$manager->disableUser($user);
			$this->fail('a deleted account cannot be suspended');
		} catch (TInvalidOperationException $e) {
			$this->assertSame('webuser_disable_status', $e->getErrorCode());
		}
	}

	public function testADeletedAccountCannotBeApprovedBackIntoUse()
	{
		$manager = $this->activeManager(['RequireApproval' => true]);
		$user = $manager->createUser('rayelan', 'correct horse');
		$stale = $manager->findUserByName('rayelan');
		$manager->deleteUser($user);

		// The object still says it is waiting for approval; the row decides.
		$this->expectException(TInvalidOperationException::class);
		$manager->approveUser($stale);
	}

	public function testSuspendingASuspendedAccountIsAllowed()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$manager->disableUser($user);
		$manager->disableUser($user);

		$this->assertSame(TWebUserManager::STATUS_DISABLED, $manager->findUserByName('rayelan')->getStatus());
	}

	// ── Tables ───────────────────────────────────────────────────────────────

	public function testATableThatCannotBeCreatedIsReportedAndTriedAgain()
	{
		$manager = WebUserTestTools::createManager([], new class () extends TestWebUserManager {
			public int $failures = 1;

			protected function createUserTable(): void
			{
				if ($this->failures-- > 0) {
					throw new \RuntimeException('disk full');
				}
				parent::createUserTable();
			}
		});

		try {
			$manager->countUsersByStatus(TWebUserManager::STATUS_ACTIVE);
			$this->fail('the failure is reported');
		} catch (TConfigurationException $e) {
			$this->assertSame('webuser_table_create_failed', $e->getErrorCode());
			$this->assertStringContainsString('disk full', $e->getMessage());
		}
		$this->assertSame(0, $manager->countUsersByStatus(TWebUserManager::STATUS_ACTIVE));
	}

	public function testTablesAreOnlyCreatedOnTheDatabasesThisKnows()
	{
		$manager = new class () extends TestWebUserManager {
			public function driverTypes(): array
			{
				return $this->getDriverTypes();
			}
		};
		$manager->setTestDbConnection(new class ('sqlsrv:Server=localhost') extends \Prado\Data\TDbConnection {
			public function setActive($value)
			{
			}

			public function getActive()
			{
				return true;
			}

			public function getDriverName()
			{
				return 'sqlsrv';
			}
		});

		$this->expectException(TConfigurationException::class);
		$this->expectExceptionMessage("The tables cannot be created on the 'sqlsrv' database");
		$manager->driverTypes();
	}
}
