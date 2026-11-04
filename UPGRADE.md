Upgrading
=========

How to move an installation, its tables, and its code from one version of this package to the
next. The newest change is at the top.


Unreleased: tables created before names and emails ignored case
---------------------------------------------------------------

Names and email addresses are now matched without regard to case on every database, and names are
unique without regard to case. A table created by this version is indexed for that. A table created
by an earlier build works unchanged, with two gaps until it is migrated:

- On PostgreSQL and SQLite, its name and email indexes are on the column as written, and the
  lookups are now on `LOWER(column)`, so sign-in and registration read the whole table.
- Its unique index on `user_name` still allows `Bob` beside `bob`. The manager refuses such a name
  in every case but two registrations at the same instant.

No column is added, renamed, or dropped, and the `user_tokens` table is unchanged. The statements
below use the default table name `users`; with a `TableName` of your own, put it in place of
`users`, and the indexes are named after it (`<table>_name`, `<table>_email`).

Back up the table first. Then:

### 1. Find names and emails that differ only in case

The new unique index cannot be built while two rows share a name in another case. This is the same
on every database:

```sql
SELECT LOWER(user_name) AS name, COUNT(*) AS accounts
FROM users GROUP BY LOWER(user_name) HAVING COUNT(*) > 1;
```

Each name it lists belongs to more than one account. Decide which keeps it, and rename the others
-- say, by appending the account id -- before step 3:

```sql
UPDATE users SET user_name = CONCAT(user_name, '-', id) WHERE id = 42;     -- MySQL
UPDATE users SET user_name = user_name || '-' || id WHERE id = 42;         -- PostgreSQL, SQLite
```

Unless `AllowDuplicateEmail` is on, look for shared addresses the same way. They do not stop the
migration, since the email index is not unique, but `findUserByEmail()` and the password reset
that uses it return the oldest of them:

```sql
SELECT LOWER(TRIM(user_email)) AS email, COUNT(*) AS accounts
FROM users WHERE user_email <> ''
GROUP BY LOWER(TRIM(user_email)) HAVING COUNT(*) > 1;
```

### 2. Trim stored email addresses

Addresses are now stored without surrounding spaces, and matched that way:

```sql
UPDATE users SET user_email = TRIM(user_email) WHERE user_email <> TRIM(user_email);
```

An address already stored is not checked again; one that is not an address is refused only when it
is next changed.

### 3. Index the folded name and email

**PostgreSQL and SQLite:**

```sql
DROP INDEX users_name;
CREATE UNIQUE INDEX users_name ON users (LOWER(user_name));
DROP INDEX users_email;
CREATE INDEX users_email ON users (LOWER(user_email));
```

On PostgreSQL, run them in a transaction so the table is never without its unique index; on a busy
table, `CREATE INDEX CONCURRENTLY` (outside a transaction) avoids locking writes while it builds.

**MySQL:** nothing to do. The default collations compare without case, so the existing indexes
already serve the lookups and keep names unique, and step 1 finds nothing. Check the columns:

```sql
SELECT COLUMN_NAME, CHARACTER_SET_NAME, COLLATION_NAME FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME IN ('user_name', 'user_email');
```

A column with a case-sensitive collation (`utf8mb4_bin`, or one ending in `_cs`) can hold names
that differ only in case, so step 1 matters there. Once it is clean, give both columns a
case-insensitive collation of their character set; for `utf8mb4`:

```sql
ALTER TABLE users
  MODIFY user_name VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  MODIFY user_email VARCHAR(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
```

MySQL rebuilds the unique index as it converts, and refuses the conversion if step 1 missed a
duplicate.

### 4. Check

The name index refuses an existing name in another case:

```sql
INSERT INTO users (user_name, user_pass, status) VALUES (UPPER('an existing name'), '', 0);
-- fails with a unique constraint violation
```


Unreleased: behavior an application notices
-------------------------------------------

None of these touch the tables.

- **PHP 8.2** is required, as PRADO 4.4 requires it.
- **Everyone is signed out once.** A session now carries a fingerprint of the account's password
  hash, and a session written by an earlier build has none. PRADO 4.4 signs everyone out once as
  well, since its session key changed. Remember-me cookies are not affected by this package; PRADO
  4.4 ignores the old ones for its own reasons.
- **Every request reads the signed-in account's row**, by primary key, to end the sessions of a
  suspended, deleted, or re-passworded account. `RevalidateSessions="false"` on the module restores
  the old behavior, and with it sessions that outlive the account's suspension.
- **Status moves throw from the wrong status.** `approveUser()` needs an account waiting for
  approval, `declineUser()` one waiting for confirmation or approval, `enableUser()` a suspended
  one, and `disableUser()` one that is not deleted. Otherwise they throw
  `TInvalidOperationException` with `webuser_approve_status`, `webuser_decline_status`,
  `webuser_enable_status`, or `webuser_disable_status`. An admin page that offers a move for any
  account checks `getStatus()` first, or catches the exception.
- **An email must be an address.** `createUser()` and `updateProfile()` throw
  `TInvalidDataValueException` with `webuser_email_invalid` for one that is not.
- **Sign-in is recorded on its own.** The manager writes `recordLogin()` when its `TAuthManager`
  signs someone in. An application that called `recordLogin()` itself after `login()` can stop;
  calling it twice is harmless.
- **Messages are ICU MessageFormat.** An application that overrides a `webuser_*` message in its
  own message file quotes an argument as `''{0}''`; written `'{0}'`, PRADO 4.4 shows a literal
  `{0}`.
- **Tables are only created on MySQL, PostgreSQL, and SQLite.** On another database the first query
  throws `TConfigurationException` with `webuser_driver_unsupported`; create the tables by hand,
  following `createUserTable()` and `createTokenTable()`, and set `AutoCreateTables="false"`.
