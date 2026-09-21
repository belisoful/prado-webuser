<?php

use Belisoful\Prado\Security\TWebUser;
use Belisoful\Prado\Security\TWebUserManager;
use Prado\Web\THttpCookie;

require_once(__DIR__ . '/../test_tools/WebUserTestTools.php');

class TWebUserTest extends PHPUnit\Framework\TestCase
{
	/**
	 * @return \TestWebUserManager a manager whose accounts can sign in as soon as they are made
	 */
	private function activeManager(): TestWebUserManager
	{
		return WebUserTestTools::createManager(['RequireEmailVerification' => false]);
	}

	public function testANewUserIsAGuestWithNoRecord()
	{
		$user = new TWebUser($this->activeManager());

		$this->assertSame(0, $user->getID());
		$this->assertSame('', $user->getEmail());
		$this->assertSame(TWebUserManager::STATUS_PENDING_EMAIL, $user->getStatus());
		$this->assertFalse($user->getCanLogin());
	}

	public function testOnlyAnActiveAccountReportsThatItMaySignIn()
	{
		$user = new TWebUser($this->activeManager());
		foreach ([
			TWebUserManager::STATUS_ACTIVE => true,
			TWebUserManager::STATUS_PENDING_EMAIL => false,
			TWebUserManager::STATUS_PENDING_APPROVAL => false,
			TWebUserManager::STATUS_DISABLED => false,
			TWebUserManager::STATUS_DELETED => false,
		] as $status => $expected) {
			$user->setStatus($status);
			$this->assertSame($expected, $user->getCanLogin(), "status {$status}");
		}
	}

	/**
	 * The fields live in the user's state, which is what the session carries, so a signed-in user
	 * is restored without reading the database again.
	 */
	public function testAUserSurvivesTheSession()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com', [
			'DisplayName' => 'Rayelan',
			'Roles' => ['editor'],
		]);

		$restored = new TWebUser($manager);
		$restored->loadFromString($user->saveToString());

		$this->assertSame($user->getID(), $restored->getID());
		$this->assertSame('rayelan', $restored->getName());
		$this->assertSame('rayelan@example.com', $restored->getEmail());
		$this->assertSame('Rayelan', $restored->getDisplayName());
		$this->assertSame($user->getStatus(), $restored->getStatus());
		$this->assertTrue($restored->isInRole('editor'));
	}

	public function testThePasswordIsNeverCarriedInTheSession()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');

		$state = (string) $user->saveToString();
		$this->assertStringNotContainsString('correct horse', $state);
		$this->assertStringNotContainsString('$2y$', $state, 'the password hash stays in the database');
	}

	public function testARememberMeCookieRoundTrips()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');

		$cookie = new THttpCookie('auth', '');
		$user->saveUserToCookie($cookie);
		$this->assertNotSame('', $cookie->getValue());
		$this->assertGreaterThan(time(), $cookie->getExpire());

		$factory = new TWebUser($manager);
		$remembered = $factory->createUserFromCookie($cookie);
		$this->assertInstanceOf(TWebUser::class, $remembered);
		$this->assertSame($user->getID(), $remembered->getID());
	}

	public function testAGuestIsNotRemembered()
	{
		$manager = $this->activeManager();
		$guest = new TWebUser($manager);
		$guest->setIsGuest(true);

		$cookie = new THttpCookie('auth', '');
		$guest->saveUserToCookie($cookie);

		$this->assertSame('', $cookie->getValue());
	}

	public function testClearingTheCookieEndsThatBrowser()
	{
		$manager = $this->activeManager();
		$user = $manager->createUser('rayelan', 'correct horse');
		$cookie = new THttpCookie('auth', '');
		$user->saveUserToCookie($cookie);

		$user->clearUserCookie($cookie);

		$factory = new TWebUser($manager);
		$this->assertNull($factory->createUserFromCookie($cookie));
	}

	public function testAnUnusableCookieIsIgnored()
	{
		$manager = $this->activeManager();
		$factory = new TWebUser($manager);

		$this->assertNull($factory->createUserFromCookie(new THttpCookie('auth', '')));
		$this->assertNull($factory->createUserFromCookie(new THttpCookie('auth', 'not-a-token')));
	}
}
