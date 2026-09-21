<?php

/**
 * Test doubles for the user manager.
 *
 * The manager reaches its database through TDbPropertiesTrait, which asks getCustomDbConnection()
 * when no ConnectionID names a TDataSourceConfig module. Overriding that is what lets a test hand
 * the manager a connection without standing up an application, so the tests exercise the real
 * queries against a real database.
 *
 * Each connection is its own in-memory SQLite database, so one test cannot see another's accounts.
 */

use Belisoful\Prado\Security\TWebUserManager;
use Prado\Data\TDbConnection;

class TestWebUserManager extends TWebUserManager
{
	/** @var null|\Prado\Data\TDbConnection the connection this manager was handed */
	private ?TDbConnection $_testConnection = null;

	public function setTestDbConnection(TDbConnection $connection): void
	{
		$this->_testConnection = $connection;
	}

	public function getTestDbConnection(): ?TDbConnection
	{
		return $this->_testConnection;
	}

	protected function getCustomDbConnection(): ?TDbConnection
	{
		return $this->_testConnection;
	}
}

class WebUserTestTools
{
	/**
	 * @return \Prado\Data\TDbConnection an open connection to a database of this test's own
	 */
	public static function createConnection(): TDbConnection
	{
		$connection = new TDbConnection('sqlite::memory:');
		$connection->setActive(true);

		return $connection;
	}

	/**
	 * @param array $properties properties to set before init, as name => value
	 * @return \TestWebUserManager an initialized manager on a fresh database
	 */
	public static function createManager(array $properties = []): TestWebUserManager
	{
		$manager = new TestWebUserManager();
		$manager->setTestDbConnection(self::createConnection());
		$manager->setID('users');
		foreach ($properties as $name => $value) {
			$manager->{'set' . $name}($value);
		}
		$manager->init(null);

		return $manager;
	}

	/**
	 * Reads an account row as the database holds it, so a test can check what was actually
	 * written rather than what the user object reports.
	 * @param \TestWebUserManager $manager the manager whose table to read
	 * @param int $id the account to read
	 * @return null|array the row, or null when there is none
	 */
	public static function readRow(TestWebUserManager $manager, int $id): ?array
	{
		$command = $manager->getTestDbConnection()->createCommand(
			'SELECT * FROM ' . $manager->getTableName() . ' WHERE id = :id'
		);
		$command->bindValue(':id', $id, PDO::PARAM_INT);
		$row = $command->query()->read();

		return $row === false ? null : $row;
	}

	/**
	 * Writes a password hash straight into the table, for testing what happens to a hash that was
	 * made by an older algorithm or cost.
	 * @param \TestWebUserManager $manager the manager whose table to write to
	 * @param int $id the account to write to
	 * @param string $hash the hash to store
	 */
	public static function writeRawPasswordHash(TestWebUserManager $manager, int $id, string $hash): void
	{
		$command = $manager->getTestDbConnection()->createCommand(
			'UPDATE ' . $manager->getTableName() . ' SET user_pass = :pass WHERE id = :id'
		);
		$command->bindValue(':pass', $hash, PDO::PARAM_STR);
		$command->bindValue(':id', $id, PDO::PARAM_INT);
		$command->execute();
	}

	/**
	 * @param \TestWebUserManager $manager the manager whose tokens to count
	 * @return int how many tokens are stored
	 */
	public static function countTokens(TestWebUserManager $manager): int
	{
		$row = $manager->getTestDbConnection()
			->createCommand('SELECT COUNT(*) AS total FROM ' . $manager->getTokenTableName())
			->query()->read();

		return $row === false ? 0 : (int) $row['total'];
	}
}
