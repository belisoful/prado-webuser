# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

UPGRADE.md describes how to migrate tables created by an earlier build, and the behavior an
application notices.

### Security

- A signed-in user is checked against its row on every request (`RevalidateSessions`, on by
  default). Suspending, declining, deleting, or purging an account, or changing its password, now
  ends its live sessions, not only its remember-me tokens. The person changing their own password
  keeps their session.
- Signing out through `TAuthManager` revokes that browser's remember-me token in the database, so a
  copied cookie stops working with it. The manager binds to the auth managers that use it once the
  application finishes initializing (`bindAuthManagers()`).
- A name that does not exist now costs a `password_hash()` at the current algorithm and cost. The
  fixed dummy hash was cost 10, so on PHP 8.4 and newer, where the default cost is 12, an unknown
  name answered about four times faster than a real one.
- Names and emails are matched without regard to case on every database, and names are unique
  without regard to case. On SQLite and PostgreSQL, `Bob` and `bob` could be two accounts, and an
  email in another case got past the duplicate check and failed a reset lookup.
- A single-use token, or an activation code, is spent only by the request whose delete removed it,
  so two requests at once cannot both use it. Code guesses are counted before they are judged, so
  guesses sent together cannot get past the limit.
- `approveUser()`, `declineUser()`, `enableUser()`, and `disableUser()` move an account only from
  the statuses that make sense, checked against the row in the same statement, and throw
  `TInvalidOperationException` otherwise. Approving a deleted account no longer brings it back.

### Fixed

- `resetPasswordWithToken()` refuses an empty password before it spends the token, so the link
  still works for a second try.
- Two registrations racing for a name or email: the later one gets `webuser_name_taken` or
  `webuser_email_taken`, not a database error or a second account.
- An email must be an address, and is stored without surrounding spaces.
- Sign-in ignores spaces around the name, as registration does.
- `recordLogin()` runs on every sign-in through `TAuthManager`, and `access_time` is kept within
  five minutes on each request and remembered-browser return.
- A failed table creation is reported with its cause and tried again, rather than masked and never
  retried. On a database other than MySQL, PostgreSQL, or SQLite, creating the tables is a clear
  configuration error.
- Search folds the pattern with the database's `LOWER()`, as it folds the columns.

### Changed

- Requires PHP 8.2, as PRADO 4.4 does; the CI matrix starts at 8.2.
- The unit suite also runs on MySQL and PostgreSQL in CI, and the workflow's actions are current.
- The error messages in `config/errorMessages.txt` are ICU MessageFormat patterns, which PRADO 4.4
  formats them as, so a quoted argument is written `''{0}''`. Written `'{0}'`, it rendered the
  literal `{0}`. The package standard checks lint every message as an ICU pattern.

### Added

- Activation codes: `issueActivationCode()` makes a six-digit code a person can type or follow
  in a link, `activateWithCode()` confirms the address with it, and `sendActivationCodeEmail()`
  mails it, filling `{code}` and `{user}` in the activation URL. A code is tied to its account,
  replaces any earlier one, works for thirty minutes, and dies after five wrong guesses.

- `updateProfile()` changes an account's email, display name, and web address, refusing an email
  another account holds, and raises `onUserUpdated`.
- `searchUsers()` and `countUsers()` find accounts by any part of the name, display name, or
  email, optionally only in some statuses -- pending approval, say -- newest first.

- `TWebUserManager`, a database user manager built on the framework's `TDbUserManager`: it
  creates accounts, checks credentials, and carries an account through email verification,
  approval, suspension, deletion, and purging. Tables are created on first use on MySQL,
  PostgreSQL, and SQLite.
- `TWebUser`, the account record. Its fields live in the user's state, so a signed-in user is
  restored from the session without another query, and the password hash never goes there.
- A status that decides what an account may do, with only `STATUS_ACTIVE` able to sign in. A
  correct password is never enough on its own.
- Passwords stored with `password_hash()`, and a hash made by an older algorithm or cost replaced
  on the next correct sign-in. A name that does not exist is checked against a dummy hash, so it
  cannot be told from a wrong password by timing.
- Single-use activation and password-reset tokens, and remember-me tokens that last until they
  expire or are revoked. A token is a selector plus a secret half, of which only a SHA-256 hash is
  stored, compared with `hash_equals()`. Changing a password, suspending, or deleting an account
  revokes every token it holds.
- Events for each step of an account's life -- `onUserCreated`, `onUserActivated`,
  `onUserApproved`, `onUserDeclined`, `onUserDisabled`, `onUserEnabled`, `onUserDeleted`,
  `onPasswordChanged` -- so mail and audit trails hang off the manager rather than off a page.
- Roles stored on the account row and restored onto the user.
- `purgeExpiredTokens()` for a cron task, and `countUsersByStatus()` for a moderation queue.
- A placeholder mailer: `sendActivationEmail()` and `sendPasswordResetEmail()` issue the token,
  put it in a configured link, and send plain text through PHP's `mail()`. A real mailer takes
  over by answering `dySendMail` and returning true, after which this package sends nothing.
  Templates, queueing, HTML parts, attachments, and bounces belong in that mailer.
