# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
