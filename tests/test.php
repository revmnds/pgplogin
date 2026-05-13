<?php

/**
 * pgplogin · integration tests.
 *
 * Plain PHP, no PHPUnit. Run with:
 *     php tests/test.php
 *
 * Generates an ephemeral OpenPGP key in a temp GNUPGHOME, drives the full
 * issue() / verify() flow against it, and asserts the failure modes.
 *
 * Requires: PHP 8.1+, gpg on PATH.
 */

declare(strict_types=1);

require_once __DIR__ . '/../pgplogin.php';

// --------- tiny test harness ---------

$tests = 0;
$failures = [];

function test(string $name, callable $fn): void
{
    global $tests, $failures;
    $tests++;
    try {
        $fn();
        fwrite(STDOUT, "  ok  $name\n");
    } catch (Throwable $e) {
        $failures[] = [$name, $e];
        fwrite(STDOUT, "  FAIL $name -- " . $e->getMessage() . "\n");
    }
}

function assertTrue(bool $cond, string $msg = 'assertion failed'): void
{
    if (! $cond) {
        throw new RuntimeException($msg);
    }
}

function assertEq($expected, $actual, string $msg = ''): void
{
    if ($expected !== $actual) {
        $e = var_export($expected, true);
        $a = var_export($actual, true);
        throw new RuntimeException(($msg ?: 'not equal') . ": expected $e, got $a");
    }
}

function assertThrows(string $exceptionClass, callable $fn): Throwable
{
    try {
        $fn();
    } catch (Throwable $e) {
        if (! ($e instanceof $exceptionClass)) {
            throw new RuntimeException(
                "expected $exceptionClass, got " . get_class($e) . ': ' . $e->getMessage()
            );
        }
        return $e;
    }
    throw new RuntimeException("expected $exceptionClass, no exception thrown");
}

// --------- gpg fixture: an ephemeral keypair ---------

if (! shell_exec('command -v gpg')) {
    fwrite(STDERR, "gpg not on PATH — cannot run integration tests.\n");
    exit(1);
}

$gnupghome = sys_get_temp_dir() . '/pgplogin-tests-' . bin2hex(random_bytes(6));
mkdir($gnupghome, 0700, true);

register_shutdown_function(function () use ($gnupghome) {
    if (is_dir($gnupghome)) {
        exec('rm -rf ' . escapeshellarg($gnupghome));
    }
});

function gpg(string $home, string $args, ?string $stdin = null): array
{
    $cmd = "GNUPGHOME=" . escapeshellarg($home)
        . " gpg --batch --no-tty --quiet --yes $args";
    $desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $desc, $pipes);
    if ($stdin !== null) {
        fwrite($pipes[0], $stdin);
    }
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($proc);
    return ['exit' => $exit, 'stdout' => $out, 'stderr' => $err];
}

fwrite(STDOUT, "Generating ephemeral keypair (this can take a few seconds)…\n");

$gen = gpg(
    $gnupghome,
    '--pinentry-mode loopback --passphrase "" '
    . '--quick-generate-key "pgplogin-test <test@example.invalid>" default default 1d'
);
if ($gen['exit'] !== 0) {
    fwrite(STDERR, "key generation failed:\n{$gen['stderr']}\n");
    exit(1);
}

$exp = gpg($gnupghome, '--armor --export pgplogin-test');
assert($exp['exit'] === 0, 'public-key export failed');
$publicKey = $exp['stdout'];

// --------- the tests ---------

fwrite(STDOUT, "\nRunning tests:\n");

test('inspect() reports fingerprint and encryption capability', function () use ($publicKey) {
    $auth = new Pgplogin();
    $info = $auth->inspect($publicKey);
    assertTrue(isset($info['fingerprint']), 'no fingerprint');
    assertTrue((bool) preg_match('/^[a-f0-9]{40}$/', $info['fingerprint']), 'bad fingerprint shape');
    assertEq(true, $info['can_encrypt'], 'fresh key should be encryption-capable');
});

test('issue() returns a well-formed pending struct', function () use ($publicKey) {
    $auth = new Pgplogin(60);
    $pending = $auth->issue($publicKey);

    foreach (['fingerprint', 'public_key', 'encrypted_token', 'token_hash', 'issued_at', 'expires_at'] as $k) {
        assertTrue(array_key_exists($k, $pending), "missing key: $k");
    }
    assertTrue(str_contains($pending['encrypted_token'], '-----BEGIN PGP MESSAGE-----'), 'no PGP MESSAGE');
    assertTrue(str_contains($pending['encrypted_token'], '-----END PGP MESSAGE-----'), 'no END marker');
    assertEq(64, strlen($pending['token_hash']), 'token_hash should be 64 hex chars');
    assertTrue($pending['expires_at'] > $pending['issued_at'], 'expires_at must follow issued_at');
});

test('verify() accepts the decrypted plaintext and returns the fingerprint', function () use ($publicKey, $gnupghome) {
    $auth = new Pgplogin();
    $pending = $auth->issue($publicKey);

    $dec = gpg($gnupghome, '--decrypt', $pending['encrypted_token']);
    assertEq(0, $dec['exit'], 'decryption failed: ' . $dec['stderr']);
    $plaintext = trim($dec['stdout']);

    $fp = $auth->verify($pending, $plaintext);
    assertEq($pending['fingerprint'], $fp, 'returned fingerprint mismatch');
});

test('verify() rejects wrong plaintext', function () use ($publicKey) {
    $auth = new Pgplogin();
    $pending = $auth->issue($publicKey);

    assertThrows(PgploginException::class, function () use ($auth, $pending) {
        $auth->verify($pending, 'deadbeefdeadbeef');
    });
});

test('verify() rejects an expired challenge', function () use ($publicKey) {
    $auth = new Pgplogin();
    $pending = $auth->issue($publicKey);
    $pending['expires_at'] = time() - 1;

    assertThrows(PgploginException::class, function () use ($auth, $pending) {
        $auth->verify($pending, 'whatever');
    });
});

test('verify() rejects an empty response', function () use ($publicKey) {
    $auth = new Pgplogin();
    $pending = $auth->issue($publicKey);

    assertThrows(PgploginException::class, function () use ($auth, $pending) {
        $auth->verify($pending, "   \n\t  ");
    });
});

test('verify() normalizes whitespace around the plaintext', function () use ($publicKey, $gnupghome) {
    $auth = new Pgplogin();
    $pending = $auth->issue($publicKey);

    $dec = gpg($gnupghome, '--decrypt', $pending['encrypted_token']);
    $plaintext = trim($dec['stdout']);

    // simulate clipboard mangling: leading/trailing whitespace and newlines
    $mangled = "\n\t  " . strtoupper($plaintext) . "  \n";
    $fp = $auth->verify($pending, $mangled);
    assertEq($pending['fingerprint'], $fp);
});

test('issue() rejects a non-key input', function () {
    $auth = new Pgplogin();
    assertThrows(PgploginException::class, function () use ($auth) {
        $auth->issue('not a key at all');
    });
});

test('constructor rejects TTL below 30s', function () {
    assertThrows(PgploginException::class, function () {
        new Pgplogin(10);
    });
});

// --------- summary ---------

fwrite(STDOUT, "\n");
if ($failures) {
    fwrite(STDOUT, count($failures) . " of $tests failed.\n");
    exit(1);
}
fwrite(STDOUT, "all $tests passed.\n");
exit(0);
