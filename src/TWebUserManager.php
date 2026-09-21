<?php

/**
 * TWebUserManager class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webuser
 * @license https://github.com/belisoful/prado-webuser/blob/master/LICENSE
 */

namespace Belisoful\Prado\Security;

use PDO;
use Prado\Data\TDbDriver;
use Prado\Exceptions\TConfigurationException;
use Prado\Exceptions\TInvalidDataValueException;
use Prado\Exceptions\TInvalidOperationException;
use Prado\Prado;
use Prado\Security\TDbUserManager;
use Prado\TPropertyValue;

/**
 * TWebUserManager class.
 *
 * A database user manager: it stores accounts, checks passwords, and carries an account through
 * registration, email verification, approval, suspension, and deletion.
 *
 * ```xml
 * <module id="users" class="TWebUserManager" ConnectionID="db" RequireApproval="true" />
 * <module id="auth" class="TAuthManager" UserManager="users" LoginPage="Login" />
 * ```
 *
 * An account's {@see getStatus status} decides what it may do, and only an active account may
 * sign in:
 *
 * | Status | Meaning |
 * | --- | --- |
 * | `STATUS_PENDING_EMAIL` | registered, waiting for the address to be confirmed |
 * | `STATUS_PENDING_APPROVAL` | confirmed, waiting for a person to let it in |
 * | `STATUS_ACTIVE` | may sign in |
 * | `STATUS_DISABLED` | suspended, refused, or banned; the name stays taken |
 * | `STATUS_DELETED` | removed, and the name stays taken so the history still reads |
 *
 * Passwords are stored with {@see password_hash}, and a hash made by an older algorithm or cost
 * is replaced on the next correct sign-in. Activation, password reset, and remember-me tokens are
 * stored as a selector and a SHA-256 hash of the secret half, so the token table cannot be used to
 * take an account over even when it is read.
 *
 * The mail this sends is a placeholder: plain text, straight to PHP's `mail()`, enough to get an
 * activation or reset link to somebody. A real mailer takes it over by answering `dySendMail`,
 * after which nothing here sends anything. Anything more -- templates, queueing, HTML parts,
 * attachments, bounces -- belongs in that mailer rather than in this package.
 *
 * @method bool dySendMail(bool $handled, string $to, string $subject, string $body)
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 1.0.0
 */
class TWebUserManager extends TDbUserManager
{
	/** Removed. The name stays taken, so old posts and logs still name somebody. */
	public const STATUS_DELETED = 0;

	/** In good standing; the only status that may sign in. */
	public const STATUS_ACTIVE = 1;

	/** Registered, waiting for the email address to be confirmed. */
	public const STATUS_PENDING_EMAIL = 2;

	/** Confirmed, waiting for a person to approve the account. */
	public const STATUS_PENDING_APPROVAL = 3;

	/** Suspended, refused, or banned. */
	public const STATUS_DISABLED = 4;

	/** A token that confirms an email address. */
	public const TOKEN_ACTIVATION = 'activation';

	/** A token that authorizes one password reset. */
	public const TOKEN_PASSWORD_RESET = 'reset';

	/** A token that signs a returning browser in. */
	public const TOKEN_COOKIE = 'cookie';

	/**
	 * Checked when no account matches, so that answering "no such user" takes as long as
	 * answering "wrong password" and cannot be told from it by timing.
	 */
	private const TIMING_HASH = '$2y$10$usesomesillystringfore.PZbsGz2AqTMgYbBOiSXZBMcSeVzKi';

	/** @var string the table holding the accounts */
	private string $_tableName = 'users';

	/** @var string the table holding the tokens */
	private string $_tokenTableName = 'user_tokens';

	/** @var bool whether missing tables are created on first use */
	private bool $_autoCreateTables = true;

	/** @var bool whether a new account must confirm its email address */
	private bool $_requireEmailVerification = true;

	/** @var bool whether a new account must be approved by a person */
	private bool $_requireApproval = false;

	/** @var bool whether two accounts may share an email address */
	private bool $_allowDuplicateEmail = false;

	/** @var int how long an activation or reset token is good for, in seconds */
	private int $_tokenLifetime = 172800;

	/** @var int how long a remember-me token is good for, in seconds */
	private int $_cookieLifetime = 2592000;

	/** @var string the address activation and reset mail is sent from */
	private string $_fromAddress = '';

	/** @var string the name shown beside the from address */
	private string $_fromName = '';

	/** @var string the site name used in the subject lines */
	private string $_siteName = '';

	/** @var string the activation link, with {token} where the token goes */
	private string $_activationUrl = '';

	/** @var string the password reset link, with {token} where the token goes */
	private string $_passwordResetUrl = '';

	/** @var bool whether the tables have been checked for */
	private bool $_tablesEnsured = false;

	/**
	 * Initializes the module, defaulting the user class to {@see \Belisoful\Prado\Security\TWebUser}.
	 * @param null|array|\Prado\Xml\TXmlElement $config the module configuration
	 */
	public function init($config)
	{
		if ($this->getUserClass() === '') {
			$this->setUserClass(TWebUser::class);
		}
		parent::init($config);
	}

	/**
	 * @return string the table holding the accounts, 'users' by default
	 */
	public function getTableName(): string
	{
		return $this->_tableName;
	}

	/**
	 * @param string $value the table holding the accounts
	 * @throws \Prado\Exceptions\TInvalidOperationException when the module is already initialized.
	 */
	public function setTableName($value): void
	{
		$this->assertUninitialized('TableName');
		$this->_tableName = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string the table holding the tokens, 'user_tokens' by default
	 */
	public function getTokenTableName(): string
	{
		return $this->_tokenTableName;
	}

	/**
	 * @param string $value the table holding the tokens
	 * @throws \Prado\Exceptions\TInvalidOperationException when the module is already initialized.
	 */
	public function setTokenTableName($value): void
	{
		$this->assertUninitialized('TokenTableName');
		$this->_tokenTableName = TPropertyValue::ensureString($value);
	}

	/**
	 * @return bool whether missing tables are created on first use, true by default
	 */
	public function getAutoCreateTables(): bool
	{
		return $this->_autoCreateTables;
	}

	/**
	 * @param bool $value whether missing tables are created on first use
	 * @throws \Prado\Exceptions\TInvalidOperationException when the module is already initialized.
	 */
	public function setAutoCreateTables($value): void
	{
		$this->assertUninitialized('AutoCreateTables');
		$this->_autoCreateTables = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return bool whether a new account must confirm its email address, true by default
	 */
	public function getRequireEmailVerification(): bool
	{
		return $this->_requireEmailVerification;
	}

	/**
	 * @param bool $value whether a new account must confirm its email address
	 */
	public function setRequireEmailVerification($value): void
	{
		$this->_requireEmailVerification = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return bool whether a new account must be approved by a person, false by default
	 */
	public function getRequireApproval(): bool
	{
		return $this->_requireApproval;
	}

	/**
	 * @param bool $value whether a new account must be approved by a person
	 */
	public function setRequireApproval($value): void
	{
		$this->_requireApproval = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return bool whether two accounts may share an email address, false by default
	 */
	public function getAllowDuplicateEmail(): bool
	{
		return $this->_allowDuplicateEmail;
	}

	/**
	 * @param bool $value whether two accounts may share an email address
	 */
	public function setAllowDuplicateEmail($value): void
	{
		$this->_allowDuplicateEmail = TPropertyValue::ensureBoolean($value);
	}

	/**
	 * @return int how long an activation or reset token is good for, two days by default
	 */
	public function getTokenLifetime(): int
	{
		return $this->_tokenLifetime;
	}

	/**
	 * @param int $value how long an activation or reset token is good for, in seconds
	 */
	public function setTokenLifetime($value): void
	{
		$this->_tokenLifetime = TPropertyValue::ensureInteger($value);
	}

	/**
	 * @return int how long a remember-me token is good for, thirty days by default
	 */
	public function getCookieLifetime(): int
	{
		return $this->_cookieLifetime;
	}

	/**
	 * @param int $value how long a remember-me token is good for, in seconds
	 */
	public function setCookieLifetime($value): void
	{
		$this->_cookieLifetime = TPropertyValue::ensureInteger($value);
	}

	/**
	 * Creates an account. Its status follows {@see getRequireEmailVerification} and
	 * {@see getRequireApproval}, so a site that asks for neither gets an account that can sign in
	 * at once.
	 *
	 * @param string $username the name to sign in with
	 * @param string $password the password, which is hashed here and never stored as given
	 * @param string $email the email address
	 * @param array $properties display name, url, roles, registered ip, or an explicit status
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the name or password is empty, or the name or email is taken.
	 * @return \Belisoful\Prado\Security\TWebUser the stored account
	 */
	public function createUser(string $username, #[\SensitiveParameter] string $password, string $email = '', array $properties = []): TWebUser
	{
		$username = trim($username);
		if ($username === '') {
			throw new TInvalidDataValueException('webuser_name_required');
		}
		if ($password === '') {
			throw new TInvalidDataValueException('webuser_password_required');
		}
		$this->ensureTables();
		if ($this->findUserByName($username) !== null) {
			throw new TInvalidDataValueException('webuser_name_taken', $username);
		}
		if ($email !== '' && !$this->getAllowDuplicateEmail() && $this->findUserByEmail($email) !== null) {
			throw new TInvalidDataValueException('webuser_email_taken', $email);
		}

		$now = time();
		$status = $properties['Status'] ?? $this->getInitialStatus();
		$roles = $properties['Roles'] ?? [];
		$db = $this->getDbConnection();
		$sql = 'INSERT INTO ' . $this->getTableName()
			. ' (user_name, user_pass, user_email, display_name, user_url, user_roles, status, registered_time, registered_ip)'
			. ' VALUES (:name, :pass, :email, :display, :url, :roles, :status, :registered, :ip)';
		$command = $db->createCommand($sql);
		$command->bindValue(':name', $username, PDO::PARAM_STR);
		$command->bindValue(':pass', $this->hashPassword($password), PDO::PARAM_STR);
		$command->bindValue(':email', $email, PDO::PARAM_STR);
		$command->bindValue(':display', (string) ($properties['DisplayName'] ?? ''), PDO::PARAM_STR);
		$command->bindValue(':url', (string) ($properties['Url'] ?? ''), PDO::PARAM_STR);
		$command->bindValue(':roles', $this->rolesToString(is_array($roles) ? $roles : [$roles]), PDO::PARAM_STR);
		$command->bindValue(':status', (int) $status, PDO::PARAM_INT);
		$command->bindValue(':registered', $now, PDO::PARAM_INT);
		$command->bindValue(':ip', (string) ($properties['RegisteredIp'] ?? ''), PDO::PARAM_STR);
		$command->execute();

		$user = $this->findUserByName($username);
		assert($user !== null);
		$this->onUserCreated($user);

		return $user;
	}

	/**
	 * @return int the status a new account starts in, from the registration settings
	 */
	public function getInitialStatus(): int
	{
		if ($this->getRequireEmailVerification()) {
			return self::STATUS_PENDING_EMAIL;
		}

		return $this->getRequireApproval() ? self::STATUS_PENDING_APPROVAL : self::STATUS_ACTIVE;
	}

	/**
	 * Checks a name and password, and upgrades the stored hash when the algorithm or cost has
	 * moved on since it was written.
	 *
	 * An account that may not sign in fails here even when the password is right, and a name that
	 * does not exist is checked against a dummy hash so that the two take the same time.
	 *
	 * @param string $username the name to check
	 * @param string $password the password to check
	 * @return null|\Belisoful\Prado\Security\TWebUser the account, or null when the credentials do not sign in
	 */
	public function verifyCredentials(string $username, #[\SensitiveParameter] string $password): ?TWebUser
	{
		$this->ensureTables();
		$row = $this->findRow('user_name', $username);
		if ($row === null) {
			password_verify($password, self::TIMING_HASH);

			return null;
		}
		if (!password_verify($password, (string) $row['user_pass'])) {
			return null;
		}

		$user = $this->populateUser($row);
		if (!$user->getCanLogin()) {
			return null;
		}
		if (password_needs_rehash((string) $row['user_pass'], PASSWORD_DEFAULT)) {
			$this->writePasswordHash($user->getID(), $this->hashPassword($password));
		}

		return $user;
	}

	/**
	 * Replaces an account's password and revokes every token it has, because a password is
	 * changed when it may have been learned.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to change
	 * @param string $password the new password
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the password is empty.
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	public function changePassword(TWebUser $user, #[\SensitiveParameter] string $password): void
	{
		$this->assertStored($user);
		if ($password === '') {
			throw new TInvalidDataValueException('webuser_password_required');
		}
		$this->writePasswordHash($user->getID(), $this->hashPassword($password));
		$this->revokeTokens($user->getID());
		$this->onPasswordChanged($user);
	}

	/**
	 * @param string $username the name to load
	 * @return null|\Belisoful\Prado\Security\TWebUser the account, or null when there is no such name
	 */
	public function findUserByName(string $username): ?TWebUser
	{
		$row = $this->findRow('user_name', $username);

		return $row === null ? null : $this->populateUser($row);
	}

	/**
	 * @param int $id the id to load
	 * @return null|\Belisoful\Prado\Security\TWebUser the account, or null when there is no such id
	 */
	public function findUserById(int $id): ?TWebUser
	{
		$row = $this->findRow('id', $id);

		return $row === null ? null : $this->populateUser($row);
	}

	/**
	 * @param string $email the address to load
	 * @return null|\Belisoful\Prado\Security\TWebUser the account, or null when no account has the address
	 */
	public function findUserByEmail(string $email): ?TWebUser
	{
		$row = $this->findRow('user_email', $email);

		return $row === null ? null : $this->populateUser($row);
	}

	/**
	 * Confirms an email address with the token that was sent to it, and moves the account on to
	 * approval or straight to active.
	 * @param string $token the token from the activation link
	 * @return null|\Belisoful\Prado\Security\TWebUser the account, or null when the token is wrong, used, or expired
	 */
	public function activateWithToken(string $token): ?TWebUser
	{
		$user = $this->consumeToken($token, self::TOKEN_ACTIVATION);
		if ($user === null || $user->getStatus() !== self::STATUS_PENDING_EMAIL) {
			return null;
		}
		$status = $this->getRequireApproval() ? self::STATUS_PENDING_APPROVAL : self::STATUS_ACTIVE;
		$this->writeStatus($user, $status);
		$this->onUserActivated($user);

		return $user;
	}

	/**
	 * Sets a new password with the token from a reset link.
	 * @param string $token the token from the reset link
	 * @param string $password the new password
	 * @throws \Prado\Exceptions\TInvalidDataValueException when the password is empty.
	 * @return null|\Belisoful\Prado\Security\TWebUser the account, or null when the token is wrong, used, or expired
	 */
	public function resetPasswordWithToken(string $token, #[\SensitiveParameter] string $password): ?TWebUser
	{
		$user = $this->consumeToken($token, self::TOKEN_PASSWORD_RESET);
		if ($user === null) {
			return null;
		}
		$this->changePassword($user, $password);

		return $user;
	}

	/**
	 * Lets an account in that was waiting for approval.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to approve
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	public function approveUser(TWebUser $user): void
	{
		$this->writeStatus($user, self::STATUS_ACTIVE);
		$this->onUserApproved($user);
	}

	/**
	 * Refuses an account. The name stays taken, so the same name cannot be registered again to
	 * get around the refusal.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to refuse
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	public function declineUser(TWebUser $user): void
	{
		$this->writeStatus($user, self::STATUS_DISABLED);
		$this->revokeTokens($user->getID());
		$this->onUserDeclined($user);
	}

	/**
	 * Suspends an account and revokes its tokens, so a remembered browser is signed out too.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to suspend
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	public function disableUser(TWebUser $user): void
	{
		$this->writeStatus($user, self::STATUS_DISABLED);
		$this->revokeTokens($user->getID());
		$this->onUserDisabled($user);
	}

	/**
	 * Returns a suspended account to good standing.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to restore
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	public function enableUser(TWebUser $user): void
	{
		$this->writeStatus($user, self::STATUS_ACTIVE);
		$this->onUserEnabled($user);
	}

	/**
	 * Marks an account deleted and revokes its tokens. The row stays, so what the account wrote
	 * still has an author; {@see purgeUser} is what removes it for good.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to delete
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	public function deleteUser(TWebUser $user): void
	{
		$this->writeStatus($user, self::STATUS_DELETED);
		$this->revokeTokens($user->getID());
		$this->onUserDeleted($user);
	}

	/**
	 * Removes an account's row and tokens for good. What the account wrote is left behind, so a
	 * caller that has such rows deals with them first.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to remove
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	public function purgeUser(TWebUser $user): void
	{
		$this->assertStored($user);
		$this->revokeTokens($user->getID());
		$command = $this->getDbConnection()->createCommand(
			'DELETE FROM ' . $this->getTableName() . ' WHERE id = :id'
		);
		$command->bindValue(':id', $user->getID(), PDO::PARAM_INT);
		$command->execute();
	}

	/**
	 * Records that the user has just signed in.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account that signed in
	 * @param string $ip the address signed in from
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	public function recordLogin(TWebUser $user, string $ip = ''): void
	{
		$this->assertStored($user);
		$now = time();
		$command = $this->getDbConnection()->createCommand(
			'UPDATE ' . $this->getTableName() . ' SET login_time = :now, access_time = :now, login_ip = :ip WHERE id = :id'
		);
		$command->bindValue(':now', $now, PDO::PARAM_INT);
		$command->bindValue(':ip', $ip, PDO::PARAM_STR);
		$command->bindValue(':id', $user->getID(), PDO::PARAM_INT);
		$command->execute();
		$user->setLoginTime($now);
		$user->setAccessTime($now);
	}

	/**
	 * Issues a token that confirms an email address.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to confirm
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 * @return string the token to put in the activation link; it is not stored and cannot be read back
	 */
	public function issueActivationToken(TWebUser $user): string
	{
		return $this->issueToken($user, self::TOKEN_ACTIVATION, $this->getTokenLifetime());
	}

	/**
	 * Issues a token that authorizes one password reset.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to reset
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 * @return string the token to put in the reset link; it is not stored and cannot be read back
	 */
	public function issuePasswordResetToken(TWebUser $user): string
	{
		return $this->issueToken($user, self::TOKEN_PASSWORD_RESET, $this->getTokenLifetime());
	}

	/**
	 * Issues a remember-me token for a returning browser.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to remember
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 * @return string the cookie value
	 */
	public function issueCookieToken(TWebUser $user): string
	{
		return $this->issueToken($user, self::TOKEN_COOKIE, $this->getCookieLifetime());
	}

	/**
	 * Reads a remember-me cookie. The token stays usable until it expires, so the browser is
	 * remembered across visits; {@see revokeCookieToken} is what ends it.
	 * @param string $value the cookie value
	 * @return null|\Belisoful\Prado\Security\TWebUser the account, or null when the cookie is wrong, expired, or its account may not sign in
	 */
	public function userFromCookieValue(string $value): ?TWebUser
	{
		$row = $this->readToken($value, self::TOKEN_COOKIE);
		if ($row === null) {
			return null;
		}
		$user = $this->findUserById((int) $row['user_id']);

		return ($user === null || !$user->getCanLogin()) ? null : $user;
	}

	/**
	 * Ends one remembered browser, or every one of an account's.
	 * @param null|string $value the cookie value to end, or null for all of them
	 * @param null|int $userId the account whose tokens to end when no cookie value is given
	 */
	public function revokeCookieToken(?string $value = null, ?int $userId = null): void
	{
		$this->ensureTables();
		if ($value !== null && $value !== '') {
			[$selector] = $this->splitToken($value);
			$command = $this->getDbConnection()->createCommand(
				'DELETE FROM ' . $this->getTokenTableName() . ' WHERE selector = :selector AND purpose = :purpose'
			);
			$command->bindValue(':selector', $selector, PDO::PARAM_STR);
			$command->bindValue(':purpose', self::TOKEN_COOKIE, PDO::PARAM_STR);
			$command->execute();

			return;
		}
		if ($userId !== null) {
			$this->revokeTokens($userId, self::TOKEN_COOKIE);
		}
	}

	/**
	 * Issues a token of any purpose. Only the selector and a hash of the secret half are stored,
	 * so what is written here cannot be turned back into a working token.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account the token belongs to
	 * @param string $purpose what the token is for
	 * @param int $lifetime how long it is good for, in seconds
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 * @return string the token, in the form selector:secret
	 */
	public function issueToken(TWebUser $user, string $purpose, int $lifetime): string
	{
		$this->assertStored($user);
		$this->ensureTables();
		$selector = bin2hex(random_bytes(8));
		$secret = bin2hex(random_bytes(32));
		$now = time();

		$command = $this->getDbConnection()->createCommand(
			'INSERT INTO ' . $this->getTokenTableName()
			. ' (user_id, purpose, selector, token_hash, expires_time, created_time)'
			. ' VALUES (:user, :purpose, :selector, :hash, :expires, :created)'
		);
		$command->bindValue(':user', $user->getID(), PDO::PARAM_INT);
		$command->bindValue(':purpose', $purpose, PDO::PARAM_STR);
		$command->bindValue(':selector', $selector, PDO::PARAM_STR);
		$command->bindValue(':hash', hash('sha256', $secret), PDO::PARAM_STR);
		$command->bindValue(':expires', $now + $lifetime, PDO::PARAM_INT);
		$command->bindValue(':created', $now, PDO::PARAM_INT);
		$command->execute();

		return $selector . ':' . $secret;
	}

	/**
	 * Spends a single-use token: the account it belongs to comes back and the token stops working.
	 * @param string $token the token to spend
	 * @param string $purpose what the token must have been issued for
	 * @return null|\Belisoful\Prado\Security\TWebUser the account, or null when the token is wrong, used, or expired
	 */
	public function consumeToken(string $token, string $purpose): ?TWebUser
	{
		$row = $this->readToken($token, $purpose);
		if ($row === null) {
			return null;
		}
		$command = $this->getDbConnection()->createCommand(
			'DELETE FROM ' . $this->getTokenTableName() . ' WHERE token_id = :id'
		);
		$command->bindValue(':id', (int) $row['token_id'], PDO::PARAM_INT);
		$command->execute();

		return $this->findUserById((int) $row['user_id']);
	}

	/**
	 * Removes every token an account holds, or only those of one purpose.
	 * @param int $userId the account whose tokens to remove
	 * @param null|string $purpose one purpose, or null for every purpose
	 */
	public function revokeTokens(int $userId, ?string $purpose = null): void
	{
		$this->ensureTables();
		$sql = 'DELETE FROM ' . $this->getTokenTableName() . ' WHERE user_id = :user';
		if ($purpose !== null) {
			$sql .= ' AND purpose = :purpose';
		}
		$command = $this->getDbConnection()->createCommand($sql);
		$command->bindValue(':user', $userId, PDO::PARAM_INT);
		if ($purpose !== null) {
			$command->bindValue(':purpose', $purpose, PDO::PARAM_STR);
		}
		$command->execute();
	}

	/**
	 * Deletes tokens that have expired. Nothing accepts them once they are past their time, so
	 * this is housekeeping: run it from a cron task.
	 * @return int how many rows were removed
	 */
	public function purgeExpiredTokens(): int
	{
		$this->ensureTables();
		$command = $this->getDbConnection()->createCommand(
			'DELETE FROM ' . $this->getTokenTableName() . ' WHERE expires_time <= :now'
		);
		$command->bindValue(':now', time(), PDO::PARAM_INT);

		return (int) $command->execute();
	}

	/**
	 * Sets an account's roles.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to change
	 * @param array $roles the roles the account holds
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	public function setUserRoles(TWebUser $user, array $roles): void
	{
		$this->assertStored($user);
		$command = $this->getDbConnection()->createCommand(
			'UPDATE ' . $this->getTableName() . ' SET user_roles = :roles WHERE id = :id'
		);
		$command->bindValue(':roles', $this->rolesToString($roles), PDO::PARAM_STR);
		$command->bindValue(':id', $user->getID(), PDO::PARAM_INT);
		$command->execute();
		$user->setRoles($roles);
	}

	/**
	 * @param int $status the status to count
	 * @return int how many accounts hold that status
	 */
	public function countUsersByStatus(int $status): int
	{
		$this->ensureTables();
		$command = $this->getDbConnection()->createCommand(
			'SELECT COUNT(*) AS total FROM ' . $this->getTableName() . ' WHERE status = :status'
		);
		$command->bindValue(':status', $status, PDO::PARAM_INT);
		$row = $command->query()->read();

		return $row === false ? 0 : (int) $row['total'];
	}

	/**
	 * @return string the address activation and reset mail is sent from
	 */
	public function getFromAddress(): string
	{
		return $this->_fromAddress;
	}

	/**
	 * @param string $value the address activation and reset mail is sent from
	 */
	public function setFromAddress($value): void
	{
		$this->_fromAddress = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string the name shown beside the from address
	 */
	public function getFromName(): string
	{
		return $this->_fromName;
	}

	/**
	 * @param string $value the name shown beside the from address
	 */
	public function setFromName($value): void
	{
		$this->_fromName = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string the site name used in the subject lines
	 */
	public function getSiteName(): string
	{
		return $this->_siteName;
	}

	/**
	 * @param string $value the site name used in the subject lines
	 */
	public function setSiteName($value): void
	{
		$this->_siteName = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string the activation link, with {token} where the token goes
	 */
	public function getActivationUrl(): string
	{
		return $this->_activationUrl;
	}

	/**
	 * @param string $value the activation link, with {token} where the token goes
	 */
	public function setActivationUrl($value): void
	{
		$this->_activationUrl = TPropertyValue::ensureString($value);
	}

	/**
	 * @return string the password reset link, with {token} where the token goes
	 */
	public function getPasswordResetUrl(): string
	{
		return $this->_passwordResetUrl;
	}

	/**
	 * @param string $value the password reset link, with {token} where the token goes
	 */
	public function setPasswordResetUrl($value): void
	{
		$this->_passwordResetUrl = TPropertyValue::ensureString($value);
	}

	/**
	 * Issues an activation token and mails the link to the account's address.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to confirm
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 * @return bool whether the message was handed to a mailer
	 */
	public function sendActivationEmail(TWebUser $user): bool
	{
		if ($user->getEmail() === '' || $this->getActivationUrl() === '') {
			return false;
		}
		$link = $this->buildLink($this->getActivationUrl(), $this->issueActivationToken($user));
		$site = $this->getSiteName();

		return $this->sendMail(
			$user->getEmail(),
			trim(($site === '' ? '' : $site . ': ') . 'confirm your email address'),
			"Hello " . $user->getDisplayName() . ",\n\n"
			. "Open this link to confirm your email address:\n\n" . $link . "\n\n"
			. "If you did not register, you can ignore this message.\n"
		);
	}

	/**
	 * Issues a reset token and mails the link to the account's address.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to reset
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 * @return bool whether the message was handed to a mailer
	 */
	public function sendPasswordResetEmail(TWebUser $user): bool
	{
		if ($user->getEmail() === '' || $this->getPasswordResetUrl() === '') {
			return false;
		}
		$link = $this->buildLink($this->getPasswordResetUrl(), $this->issuePasswordResetToken($user));
		$site = $this->getSiteName();

		return $this->sendMail(
			$user->getEmail(),
			trim(($site === '' ? '' : $site . ': ') . 'reset your password'),
			"Hello " . $user->getDisplayName() . ",\n\n"
			. "Open this link to set a new password:\n\n" . $link . "\n\n"
			. "If you did not ask for this, you can ignore this message; your password stays as it is.\n"
		);
	}

	/**
	 * Sends a message.
	 *
	 * This is deliberately the smallest thing that works, and it is where a real mailer takes
	 * over: a behavior that answers `dySendMail` and returns true handles the message instead,
	 * and nothing else in this package changes. Templates, queueing, HTML parts, attachments, and
	 * bounce handling belong in that mailer, not here.
	 *
	 * @param string $to the address to send to
	 * @param string $subject the subject line
	 * @param string $body the message, as plain text
	 * @return bool whether the message was handed to a mailer
	 */
	public function sendMail(string $to, string $subject, string $body): bool
	{
		if ($to === '') {
			return false;
		}
		if ($this->dySendMail(false, $to, $subject, $body) === true) {
			return true;
		}

		return $this->deliverMail($to, $subject, $body);
	}

	/**
	 * Hands a message to PHP's mail(). Overridden in tests, and bypassed entirely once a mailer
	 * answers {@see sendMail}'s `dySendMail`.
	 * @param string $to the address to send to
	 * @param string $subject the subject line
	 * @param string $body the message, as plain text
	 * @return bool whether mail() accepted the message
	 */
	protected function deliverMail(string $to, string $subject, string $body): bool
	{
		$headers = ['Content-Type: text/plain; charset=UTF-8'];
		if ($this->getFromAddress() !== '') {
			$name = $this->getFromName();
			$headers[] = 'From: ' . ($name === '' ? $this->getFromAddress() : $name . ' <' . $this->getFromAddress() . '>');
		}

		return mail($to, $subject, $body, implode("\r\n", $headers));
	}

	/**
	 * @param string $url the link, with {token} where the token goes
	 * @param string $token the token to put in it
	 * @return string the link to send
	 */
	protected function buildLink(string $url, string $token): string
	{
		return str_replace('{token}', rawurlencode($token), $url);
	}

	/**
	 * Raised after an account is created.
	 * @param \Belisoful\Prado\Security\TWebUser $user the new account
	 */
	public function onUserCreated(TWebUser $user): void
	{
		$this->raiseEvent('onUserCreated', $this, $user);
	}

	/**
	 * Raised after an email address is confirmed.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account
	 */
	public function onUserActivated(TWebUser $user): void
	{
		$this->raiseEvent('onUserActivated', $this, $user);
	}

	/**
	 * Raised after an account is approved.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account
	 */
	public function onUserApproved(TWebUser $user): void
	{
		$this->raiseEvent('onUserApproved', $this, $user);
	}

	/**
	 * Raised after an account is refused.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account
	 */
	public function onUserDeclined(TWebUser $user): void
	{
		$this->raiseEvent('onUserDeclined', $this, $user);
	}

	/**
	 * Raised after an account is suspended.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account
	 */
	public function onUserDisabled(TWebUser $user): void
	{
		$this->raiseEvent('onUserDisabled', $this, $user);
	}

	/**
	 * Raised after a suspended account is restored.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account
	 */
	public function onUserEnabled(TWebUser $user): void
	{
		$this->raiseEvent('onUserEnabled', $this, $user);
	}

	/**
	 * Raised after an account is deleted.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account
	 */
	public function onUserDeleted(TWebUser $user): void
	{
		$this->raiseEvent('onUserDeleted', $this, $user);
	}

	/**
	 * Raised after a password is changed.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account
	 */
	public function onPasswordChanged(TWebUser $user): void
	{
		$this->raiseEvent('onPasswordChanged', $this, $user);
	}

	/**
	 * @param string $password the password to hash
	 * @return string the hash to store
	 */
	protected function hashPassword(#[\SensitiveParameter] string $password): string
	{
		return password_hash($password, PASSWORD_DEFAULT);
	}

	/**
	 * Reads a token and checks it, in constant time against the stored hash.
	 * @param string $token the token as it was given out
	 * @param string $purpose what the token must have been issued for
	 * @return null|array the token row, or null when the token is wrong or expired
	 */
	protected function readToken(string $token, string $purpose): ?array
	{
		$this->ensureTables();
		[$selector, $secret] = $this->splitToken($token);
		if ($selector === '' || $secret === '') {
			return null;
		}
		$command = $this->getDbConnection()->createCommand(
			'SELECT token_id, user_id, token_hash, expires_time FROM ' . $this->getTokenTableName()
			. ' WHERE selector = :selector AND purpose = :purpose'
		);
		$command->bindValue(':selector', $selector, PDO::PARAM_STR);
		$command->bindValue(':purpose', $purpose, PDO::PARAM_STR);
		$row = $command->query()->read();
		if ($row === false) {
			return null;
		}
		// hash_equals, not ===: a token is a secret, and comparing it byte by byte leaks where it
		// stopped matching.
		if (!hash_equals((string) $row['token_hash'], hash('sha256', $secret))) {
			return null;
		}
		if ((int) $row['expires_time'] <= time()) {
			return null;
		}

		return $row;
	}

	/**
	 * @param string $token the token to split
	 * @return array the selector and the secret half, either empty when the token is malformed
	 */
	protected function splitToken(string $token): array
	{
		$parts = explode(':', $token, 2);

		return [$parts[0] ?? '', $parts[1] ?? ''];
	}

	/**
	 * @param string $column the column to match
	 * @param mixed $value what to match it against
	 * @return null|array the account row, or null when nothing matches
	 */
	protected function findRow(string $column, $value): ?array
	{
		$this->ensureTables();
		$command = $this->getDbConnection()->createCommand(
			'SELECT * FROM ' . $this->getTableName() . ' WHERE ' . $column . ' = :value'
		);
		$command->bindValue(':value', $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
		$row = $command->query()->read();

		return $row === false ? null : $row;
	}

	/**
	 * Turns an account row into a user.
	 * @param array $row the account row
	 * @return \Belisoful\Prado\Security\TWebUser the user
	 */
	protected function populateUser(array $row): TWebUser
	{
		$user = Prado::createComponent($this->getUserClass(), $this);
		assert($user instanceof TWebUser);
		$user->setIsGuest(false);
		$user->setID((int) $row['id']);
		$user->setName((string) $row['user_name']);
		$user->setEmail((string) ($row['user_email'] ?? ''));
		$user->setDisplayName((string) ($row['display_name'] ?? ''));
		$user->setUrl((string) ($row['user_url'] ?? ''));
		$user->setStatus((int) $row['status']);
		$user->setRegisteredTime((int) ($row['registered_time'] ?? 0));
		$user->setRegisteredIp((string) ($row['registered_ip'] ?? ''));
		$user->setLoginTime((int) ($row['login_time'] ?? 0));
		$user->setAccessTime((int) ($row['access_time'] ?? 0));
		$roles = trim((string) ($row['user_roles'] ?? ''));
		if ($roles !== '') {
			$user->setRoles($roles);
		}

		return $user;
	}

	/**
	 * @param array $roles the roles to store
	 * @return string the roles as the column holds them
	 */
	protected function rolesToString(array $roles): string
	{
		return implode(',', array_filter(array_map(fn ($role) => trim((string) $role), $roles), fn ($role) => $role !== ''));
	}

	/**
	 * Writes an account's status, and keeps the user in step with the row.
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to change
	 * @param int $status the status to write
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account is not stored.
	 */
	protected function writeStatus(TWebUser $user, int $status): void
	{
		$this->assertStored($user);
		$command = $this->getDbConnection()->createCommand(
			'UPDATE ' . $this->getTableName() . ' SET status = :status WHERE id = :id'
		);
		$command->bindValue(':status', $status, PDO::PARAM_INT);
		$command->bindValue(':id', $user->getID(), PDO::PARAM_INT);
		$command->execute();
		$user->setStatus($status);
	}

	/**
	 * @param int $userId the account to write to
	 * @param string $hash the password hash to store
	 */
	protected function writePasswordHash(int $userId, string $hash): void
	{
		$command = $this->getDbConnection()->createCommand(
			'UPDATE ' . $this->getTableName() . ' SET user_pass = :pass WHERE id = :id'
		);
		$command->bindValue(':pass', $hash, PDO::PARAM_STR);
		$command->bindValue(':id', $userId, PDO::PARAM_INT);
		$command->execute();
	}

	/**
	 * @param \Belisoful\Prado\Security\TWebUser $user the account to check
	 * @throws \Prado\Exceptions\TInvalidOperationException when the account has no row to act on.
	 */
	protected function assertStored(TWebUser $user): void
	{
		if ($user->getID() <= 0) {
			throw new TInvalidOperationException('webuser_user_not_stored', $user->getName());
		}
	}

	/**
	 * Checks for the tables, creating them when they are missing and {@see getAutoCreateTables}
	 * allows.
	 * @throws \Prado\Exceptions\TConfigurationException when a table is missing and cannot be created.
	 */
	protected function ensureTables(): void
	{
		if ($this->_tablesEnsured) {
			return;
		}
		$this->_tablesEnsured = true;
		$db = $this->getDbConnection();
		foreach ([$this->getTableName() => 'createUserTable', $this->getTokenTableName() => 'createTokenTable'] as $table => $creator) {
			try {
				$db->createCommand('SELECT * FROM ' . $table . ' WHERE 0=1')->query()->close();
			} catch (\Exception $e) {
				if (!$this->getAutoCreateTables()) {
					throw new TConfigurationException('webuser_table_nonexistent', $table);
				}
				$this->{$creator}();
			}
		}
	}

	/**
	 * Creates the accounts table.
	 */
	protected function createUserTable(): void
	{
		$db = $this->getDbConnection();
		$table = $this->getTableName();
		[$autoType, $autoAttributes, $textType] = $this->getDriverTypes();

		$db->createCommand('CREATE TABLE ' . $table . ' ('
			. 'id ' . $autoType . ' PRIMARY KEY' . $autoAttributes . ', '
			. 'user_name VARCHAR(128) NOT NULL, '
			. 'user_pass VARCHAR(255) NOT NULL, '
			. 'user_email VARCHAR(191), '
			. 'display_name VARCHAR(191), '
			. 'user_url VARCHAR(255), '
			. 'user_roles VARCHAR(255), '
			. 'status INTEGER NOT NULL DEFAULT ' . self::STATUS_PENDING_EMAIL . ', '
			. 'registered_time INTEGER NOT NULL DEFAULT 0, '
			. 'registered_ip VARCHAR(45), '
			. 'login_time INTEGER NOT NULL DEFAULT 0, '
			. 'login_ip VARCHAR(45), '
			. 'access_time INTEGER NOT NULL DEFAULT 0'
			. ')')->execute();
		$db->createCommand('CREATE UNIQUE INDEX ' . $table . '_name ON ' . $table . ' (user_name)')->execute();
		$db->createCommand('CREATE INDEX ' . $table . '_email ON ' . $table . ' (user_email)')->execute();
		$db->createCommand('CREATE INDEX ' . $table . '_status ON ' . $table . ' (status)')->execute();
	}

	/**
	 * Creates the tokens table.
	 */
	protected function createTokenTable(): void
	{
		$db = $this->getDbConnection();
		$table = $this->getTokenTableName();
		[$autoType, $autoAttributes] = $this->getDriverTypes();

		$db->createCommand('CREATE TABLE ' . $table . ' ('
			. 'token_id ' . $autoType . ' PRIMARY KEY' . $autoAttributes . ', '
			. 'user_id INTEGER NOT NULL, '
			. 'purpose VARCHAR(32) NOT NULL, '
			. 'selector VARCHAR(32) NOT NULL, '
			. 'token_hash VARCHAR(64) NOT NULL, '
			. 'expires_time INTEGER NOT NULL DEFAULT 0, '
			. 'created_time INTEGER NOT NULL DEFAULT 0'
			. ')')->execute();
		$db->createCommand('CREATE UNIQUE INDEX ' . $table . '_selector ON ' . $table . ' (selector)')->execute();
		$db->createCommand('CREATE INDEX ' . $table . '_user ON ' . $table . ' (user_id, purpose)')->execute();
		$db->createCommand('CREATE INDEX ' . $table . '_expires ON ' . $table . ' (expires_time)')->execute();
	}

	/**
	 * @return array the auto-increment type, its attributes, and the long text type for this driver
	 */
	protected function getDriverTypes(): array
	{
		switch ($this->getDbConnection()->getDriverName()) {
			case TDbDriver::DRIVER_SQLITE:
				return ['INTEGER', ' AUTOINCREMENT', 'MEDIUMTEXT'];
			case TDbDriver::DRIVER_PGSQL:
				return ['SERIAL', '', 'TEXT'];
			default:	// mysql
				return ['INTEGER', ' AUTO_INCREMENT', 'MEDIUMTEXT'];
		}
	}
}
