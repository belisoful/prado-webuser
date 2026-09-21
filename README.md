prado-webuser
=============

Database user manager for PRADO: registration, email verification, approval, password reset, and
remember-me login.

```xml
<modules>
	<module id="users" class="TWebUserManager" ConnectionID="db" RequireApproval="true" />
	<module id="auth" class="TAuthManager" UserManager="users" LoginPage="Login" />
</modules>
```

```php
$users = $this->getApplication()->getModule('users');
$user = $users->createUser('rayelan', $password, 'rayelan@example.com');
$link = 'https://example.com/activate?token=' . urlencode($users->issueActivationToken($user));
```


Installation
------------

```
composer require belisoful/prado-webuser
```

Loading the extension by its package name (`<module id="belisoful/prado-webuser" />`) also works;
the class then comes from `extra.prado.bootstrap`. The `users` and `user_tokens` tables are
created on first use unless `AutoCreateTables` says otherwise.


What an account may do
----------------------

An account's status decides, and only an active account may sign in -- the password being right is
never enough on its own.

| Status | Meaning |
| --- | --- |
| `STATUS_PENDING_EMAIL` | registered, waiting for the address to be confirmed |
| `STATUS_PENDING_APPROVAL` | confirmed, waiting for a person to let it in |
| `STATUS_ACTIVE` | may sign in |
| `STATUS_DISABLED` | suspended, refused, or banned; the name stays taken |
| `STATUS_DELETED` | removed; the row and name stay, so old posts still have an author |

Where a new account starts follows `RequireEmailVerification` (on by default) and
`RequireApproval` (off). `purgeUser()` is what removes a row for good.


Registration
------------

```php
$user = $users->createUser($name, $password, $email, ['DisplayName' => 'Rayelan']);
$token = $users->issueActivationToken($user);   // put in the link you email
$users->activateWithToken($token);              // confirms the address
$users->approveUser($user);                     // when RequireApproval is on
```

Password reset is the same shape: `issuePasswordResetToken()`, then
`resetPasswordWithToken($token, $newPassword)`.

Every step raises an event -- `onUserCreated`, `onUserActivated`, `onUserApproved`,
`onUserDeclined`, `onUserDisabled`, `onUserEnabled`, `onUserDeleted`, `onPasswordChanged` -- so
sending the mail, writing the audit line, or seeding a profile hangs off the manager rather than
off whichever page happened to call it.


Passwords and tokens
--------------------

Passwords are stored with `password_hash()`, and a hash left behind by an older algorithm or cost
is replaced on the next correct sign-in.

A token is a selector and a secret half. Only the selector and a SHA-256 hash of the secret are
stored, and they are compared with `hash_equals()`, so the token table cannot be used to take an
account over even by somebody who can read it. Activation and reset tokens are single use;
remember-me tokens last until they expire or are revoked. Changing a password revokes every token
the account holds, and so does suspending or deleting it.

`purgeExpiredTokens()` is housekeeping for a cron task; nothing accepts an expired token either
way.


Email is a placeholder
----------------------

This package sends plain text straight to PHP's `mail()`. That is enough to get an activation or
reset link to somebody, and it is meant to be replaced:

```xml
<module id="users" class="TWebUserManager" ConnectionID="db"
        FromAddress="no-reply@example.com" SiteName="Example"
        ActivationUrl="https://example.com/activate?token={token}"
        PasswordResetUrl="https://example.com/reset?token={token}" />
```

```php
$users->sendActivationEmail($user);     // issues the token and mails the link
$users->sendPasswordResetEmail($user);
```

A real mailer takes over by answering `dySendMail` and returning true, after which nothing here
sends anything:

```php
class MyMailerBehavior extends TBehavior
{
	public function dySendMail($handled, $to, $subject, $body)
	{
		// hand it to Symfony Mailer, or whatever is doing the sending
		return true;
	}
}
```

Templates, queueing, HTML parts, attachments, and bounce handling belong in that mailer. Do not
grow them here.


Development
-----------

`composer fulltest` runs the full check: compile, code style, static analysis, unit tests.
`composer integration` installs the package into a throwaway consumer project and checks the
wiring. See AGENTS.md for the conventions this package holds to.
