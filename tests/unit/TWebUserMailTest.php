<?php

use Prado\Util\TBehavior;

require_once(__DIR__ . '/../test_tools/WebUserTestTools.php');

/** Captures what would have been mailed, so no test sends anything. */
class CapturingWebUserManager extends TestWebUserManager
{
	/** @var array every message that reached the transport */
	public array $sent = [];

	protected function deliverMail(string $to, string $subject, string $body): bool
	{
		$this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];

		return true;
	}
}

/** Stands in for the mailer this package will hand off to. */
class TakeoverMailerBehavior extends TBehavior
{
	/** @var array every message the behavior took over */
	public array $sent = [];

	public function dySendMail($handled, $to, $subject, $body)
	{
		$this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];

		return true;
	}
}

class TWebUserMailTest extends PHPUnit\Framework\TestCase
{
	/**
	 * @param array $properties settings to apply before init
	 * @return \CapturingWebUserManager a manager that captures mail instead of sending it
	 */
	private function manager(array $properties = []): CapturingWebUserManager
	{
		$manager = new CapturingWebUserManager();
		$manager->setTestDbConnection(WebUserTestTools::createConnection());
		$manager->setID('users');
		$properties += [
			'ActivationUrl' => 'https://example.com/activate?token={token}',
			'PasswordResetUrl' => 'https://example.com/reset?token={token}',
			'SiteName' => 'Example',
		];
		foreach ($properties as $name => $value) {
			$manager->{'set' . $name}($value);
		}
		$manager->init(null);

		return $manager;
	}

	/**
	 * @param string $body the message that was sent
	 * @return string the token out of the link in it
	 */
	private function tokenFromBody(string $body): string
	{
		$this->assertMatchesRegularExpression('/token=([^\s]+)/', $body);
		preg_match('/token=([^\s]+)/', $body, $match);

		return rawurldecode($match[1]);
	}

	public function testTheActivationLinkCarriesAWorkingToken()
	{
		// The mail is only a carrier: what matters is that the token in it activates the account.
		$manager = $this->manager();
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com');

		$this->assertTrue($manager->sendActivationEmail($user));
		$this->assertCount(1, $manager->sent);
		$this->assertSame('rayelan@example.com', $manager->sent[0]['to']);
		$this->assertStringContainsString('Example', $manager->sent[0]['subject']);

		$activated = $manager->activateWithToken($this->tokenFromBody($manager->sent[0]['body']));
		$this->assertNotNull($activated);
		$this->assertTrue($activated->getCanLogin());
	}

	public function testTheResetLinkCarriesAWorkingToken()
	{
		$manager = $this->manager(['RequireEmailVerification' => false]);
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com');

		$this->assertTrue($manager->sendPasswordResetEmail($user));
		$token = $this->tokenFromBody($manager->sent[0]['body']);

		$this->assertNotNull($manager->resetPasswordWithToken($token, 'a new password'));
		$this->assertNotNull($manager->verifyCredentials('rayelan', 'a new password'));
	}

	public function testATokenWithUrlUnsafeCharactersSurvivesTheLink()
	{
		$manager = $this->manager();
		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com');
		$manager->sendActivationEmail($user);

		// The token holds a colon between its halves, which has to come back intact.
		$token = $this->tokenFromBody($manager->sent[0]['body']);
		$this->assertStringContainsString(':', $token);
		$this->assertNotNull($manager->activateWithToken($token));
	}

	public function testNothingIsSentWithoutAnAddressOrALink()
	{
		$manager = $this->manager();
		$withoutEmail = $manager->createUser('rayelan', 'correct horse');
		$this->assertFalse($manager->sendActivationEmail($withoutEmail));

		$unconfigured = $this->manager(['ActivationUrl' => '', 'PasswordResetUrl' => '']);
		$user = $unconfigured->createUser('hobie', 'correct horse', 'hobie@example.com');
		$this->assertFalse($unconfigured->sendActivationEmail($user));
		$this->assertFalse($unconfigured->sendPasswordResetEmail($user));

		$this->assertSame([], $manager->sent);
		$this->assertSame([], $unconfigured->sent);
	}

	/**
	 * The seam the real mailer will use: it answers dySendMail, and this package stops sending.
	 */
	public function testAMailerBehaviorTakesOverEntirely()
	{
		$manager = $this->manager();
		$mailer = new TakeoverMailerBehavior();
		$manager->attachBehavior('mailer', $mailer);

		$user = $manager->createUser('rayelan', 'correct horse', 'rayelan@example.com');
		$this->assertTrue($manager->sendActivationEmail($user));

		$this->assertCount(1, $mailer->sent, 'the behavior was handed the message');
		$this->assertSame('rayelan@example.com', $mailer->sent[0]['to']);
		$this->assertSame([], $manager->sent, 'the built-in transport was not used');
	}

	public function testSendMailRefusesAnEmptyAddress()
	{
		$manager = $this->manager();
		$this->assertFalse($manager->sendMail('', 'subject', 'body'));
		$this->assertSame([], $manager->sent);
	}
}
