<?php

/**
 * TWebUser class file
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @link https://github.com/belisoful/prado-webuser
 * @license https://github.com/belisoful/prado-webuser/blob/master/LICENSE
 */

namespace Belisoful\Prado\Security;

use Prado\Security\TDbUser;
use Prado\TPropertyValue;
use Prado\Web\THttpCookie;

/**
 * TWebUser class.
 *
 * The user record {@see \Belisoful\Prado\Security\TWebUserManager} stores and restores: a name, a
 * password hash, an email address, a status, and the times the account was registered and last
 * seen.
 *
 * Every field is held in the user's state, which is what {@see \Prado\Security\TUser::saveToString}
 * writes to the session, so a signed-in user is restored without reading the database again.
 *
 * The three methods the framework calls on the factory instance -- {@see validateUser},
 * {@see createUser}, and {@see createUserFromCookie} -- all hand the work to the manager, which
 * owns every query the package makes.
 *
 * @author Brad Anderson <belisoful@icloud.com>
 * @since 1.0.0
 */
class TWebUser extends TDbUser
{
	/**
	 * @param mixed $hideAutoID
	 * @return int the id of the user record, 0 for a user that is not stored
	 */
	public function getID($hideAutoID = true)
	{
		return (int) $this->getState('id', 0);
	}

	/**
	 * @param int $value the id of the user record
	 */
	public function setID($value)
	{
		$this->setState('id', TPropertyValue::ensureInteger($value), 0);
	}

	/**
	 * @return string the email address of the user
	 */
	public function getEmail(): string
	{
		return (string) $this->getState('email', '');
	}

	/**
	 * @param string $value the email address of the user
	 */
	public function setEmail($value): void
	{
		$this->setState('email', TPropertyValue::ensureString($value), '');
	}

	/**
	 * @return string the name shown for the user, falling back to the user name
	 */
	public function getDisplayName(): string
	{
		$displayName = (string) $this->getState('displayName', '');

		return $displayName === '' ? (string) $this->getName() : $displayName;
	}

	/**
	 * @param string $value the name shown for the user
	 */
	public function setDisplayName($value): void
	{
		$this->setState('displayName', TPropertyValue::ensureString($value), '');
	}

	/**
	 * @return string the user's own web address
	 */
	public function getUrl(): string
	{
		return (string) $this->getState('url', '');
	}

	/**
	 * @param string $value the user's own web address
	 */
	public function setUrl($value): void
	{
		$this->setState('url', TPropertyValue::ensureString($value), '');
	}

	/**
	 * @return int what the account is allowed to do, one of the TWebUserManager STATUS_* values
	 */
	public function getStatus(): int
	{
		return (int) $this->getState('status', TWebUserManager::STATUS_PENDING_EMAIL);
	}

	/**
	 * @param int $value one of the TWebUserManager STATUS_* values
	 */
	public function setStatus($value): void
	{
		$this->setState('status', TPropertyValue::ensureInteger($value), TWebUserManager::STATUS_PENDING_EMAIL);
	}

	/**
	 * @return bool whether the account may sign in, which only an active account may
	 */
	public function getCanLogin(): bool
	{
		return $this->getStatus() === TWebUserManager::STATUS_ACTIVE;
	}

	/**
	 * @return int when the account was created, as a unix timestamp
	 */
	public function getRegisteredTime(): int
	{
		return (int) $this->getState('registeredTime', 0);
	}

	/**
	 * @param int $value when the account was created, as a unix timestamp
	 */
	public function setRegisteredTime($value): void
	{
		$this->setState('registeredTime', TPropertyValue::ensureInteger($value), 0);
	}

	/**
	 * @return string the address the account was registered from
	 */
	public function getRegisteredIp(): string
	{
		return (string) $this->getState('registeredIp', '');
	}

	/**
	 * @param string $value the address the account was registered from
	 */
	public function setRegisteredIp($value): void
	{
		$this->setState('registeredIp', TPropertyValue::ensureString($value), '');
	}

	/**
	 * @return int when the user last signed in, as a unix timestamp
	 */
	public function getLoginTime(): int
	{
		return (int) $this->getState('loginTime', 0);
	}

	/**
	 * @param int $value when the user last signed in, as a unix timestamp
	 */
	public function setLoginTime($value): void
	{
		$this->setState('loginTime', TPropertyValue::ensureInteger($value), 0);
	}

	/**
	 * @return int when the user was last seen, as a unix timestamp
	 */
	public function getAccessTime(): int
	{
		return (int) $this->getState('accessTime', 0);
	}

	/**
	 * @param int $value when the user was last seen, as a unix timestamp
	 */
	public function setAccessTime($value): void
	{
		$this->setState('accessTime', TPropertyValue::ensureInteger($value), 0);
	}

	/**
	 * Checks a name and password. Called on the factory user by
	 * {@see \Prado\Security\TDbUserManager::validateUser}.
	 * @param string $username the name to check
	 * @param string $password the password to check
	 * @return bool whether the credentials belong to an account that may sign in
	 */
	public function validateUser($username, #[\SensitiveParameter] $password)
	{
		return $this->getWebUserManager()->verifyCredentials($username, $password) !== null;
	}

	/**
	 * Loads a user by name. Called on the factory user by
	 * {@see \Prado\Security\TDbUserManager::getUser}.
	 * @param string $username the name to load
	 * @return null|\Belisoful\Prado\Security\TWebUser the user, or null when there is no such account
	 */
	public function createUser($username)
	{
		return $this->getWebUserManager()->findUserByName($username);
	}

	/**
	 * Restores a user from a remember-me cookie.
	 * @param \Prado\Web\THttpCookie $cookie the cookie the browser sent
	 * @return null|\Belisoful\Prado\Security\TWebUser the user, or null when the cookie is unusable
	 */
	public function createUserFromCookie($cookie)
	{
		return $this->getWebUserManager()->userFromCookieValue((string) $cookie->getValue());
	}

	/**
	 * Writes a remember-me cookie for this user, replacing whatever it held.
	 * @param \Prado\Web\THttpCookie $cookie the cookie to write
	 */
	public function saveUserToCookie($cookie)
	{
		if ($this->getIsGuest()) {
			return;
		}
		$manager = $this->getWebUserManager();
		$cookie->setValue($manager->issueCookieToken($this));
		$cookie->setExpire(time() + $manager->getCookieLifetime());
	}

	/**
	 * Clears this user's remember-me token, so a cookie that still holds it stops working.
	 * @param \Prado\Web\THttpCookie $cookie the cookie the browser sent, when there is one
	 */
	public function clearUserCookie(?THttpCookie $cookie = null): void
	{
		$this->getWebUserManager()->revokeCookieToken($cookie === null ? null : (string) $cookie->getValue());
	}

	/**
	 * @return \Belisoful\Prado\Security\TWebUserManager the manager that stores this user
	 */
	protected function getWebUserManager(): TWebUserManager
	{
		$manager = $this->getManager();
		assert($manager instanceof TWebUserManager);

		return $manager;
	}
}
