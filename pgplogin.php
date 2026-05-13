<?php

/**
 * pgplogin -- simple OpenPGP passwordless login for PHP, decryption-challenge flow.
 * One file, one class, no Composer, no PECL.
 *
 * Drop this file into your project, require it, and use the Pgplogin class.
 *
 *     require_once 'pgplogin.php';
 *
 *     $auth = new Pgplogin();
 *
 *     // step 1 -- issue a challenge from a pasted public key
 *     $pending = $auth->issue($publicKey);
 *     $_SESSION['pgp_pending'] = $pending;      // or DB, Redis, anywhere
 *     // show $pending['encrypted_token'] to the user
 *
 *     // step 2 -- verify the plaintext the user pastes back
 *     try {
 *         $fingerprint = $auth->verify($_SESSION['pgp_pending'], $_POST['response']);
 *         unset($_SESSION['pgp_pending']);      // anti-replay: drop on success
 *         $_SESSION['user'] = $fingerprint;
 *     } catch (PgploginException $e) {
 *         echo $e->getMessage();
 *     }
 *
 * The cleartext token never persists. Only sha256(token) lives in the pending
 * struct -- a session-store leak does not let an attacker impersonate the user.
 *
 * Requirements: PHP 8.1+ and the `gpg` binary on the server.
 * No PECL extensions. No Composer. License: MIT.
 */

if (! class_exists('PgploginException', false)) {
    class PgploginException extends RuntimeException {}
}

if (! class_exists('Pgplogin', false)) {

class Pgplogin
{
    const DEFAULT_TTL_SECONDS = 300;

    /** 8 random bytes -> 16 hex chars. Unguessable, short enough to paste. */
    const TOKEN_BYTES = 8;

    private $ttlSeconds;
    private $gpgBinary;

    public function __construct($ttlSeconds = self::DEFAULT_TTL_SECONDS, $gpgBinary = 'gpg')
    {
        if ($ttlSeconds < 30) {
            throw new PgploginException('TTL must be at least 30 seconds.');
        }
        $this->ttlSeconds = (int) $ttlSeconds;
        $this->gpgBinary = (string) $gpgBinary;
    }

    /**
     * Build a login challenge for the holder of $armoredPublicKey.
     *
     * Returns an associative array safe to store in $_SESSION / DB / cache:
     *   fingerprint     -- lowercase v4 fingerprint (40 hex chars)
     *   public_key      -- normalized ASCII-armored public key
     *   encrypted_token -- PGP MESSAGE -- show this to the user
     *   token_hash      -- sha256 of the secret plaintext
     *   issued_at       -- unix timestamp
     *   expires_at      -- unix timestamp
     */
    public function issue($armoredPublicKey)
    {
        $armoredPublicKey = $this->normalizeArmored($armoredPublicKey);
        $this->assertLooksLikePublicKey($armoredPublicKey);

        $self = $this;
        return $this->withTempKeyring(function ($home) use ($self, $armoredPublicKey) {
            $imported = $self->runGpg($home, array('--import'), $armoredPublicKey);
            if ($imported['exit'] !== 0) {
                throw new PgploginException(
                    'Could not import OpenPGP public key. Paste the full ASCII-armored block.'
                );
            }

            $keyInfo = $self->listPrimaryKey($home);
            if ($keyInfo === null) {
                throw new PgploginException('No usable key was imported.');
            }
            if (! $keyInfo['can_encrypt']) {
                throw new PgploginException(
                    'This key has no usable encryption subkey. '
                    .'Decryption-flow login requires an encryption-capable subkey.'
                );
            }

            $token = bin2hex(random_bytes(self::TOKEN_BYTES));

            $enc = $self->runGpg($home, array(
                '--encrypt',
                '--armor',
                '--trust-model', 'always',
                '--recipient', $keyInfo['fingerprint'],
            ), $token);

            if ($enc['exit'] !== 0 || $enc['stdout'] === '') {
                throw new PgploginException('Encryption failed: '.trim($enc['stderr']));
            }

            $now = time();

            return array(
                'fingerprint'     => $keyInfo['fingerprint'],
                'public_key'      => $armoredPublicKey,
                'encrypted_token' => $enc['stdout'],
                'token_hash'      => hash('sha256', $token),
                'issued_at'       => $now,
                'expires_at'      => $now + $self->getTtlSeconds(),
            );
        });
    }

    /**
     * Verify the plaintext the user pasted back. Returns the fingerprint on
     * success; throws PgploginException on expiry / mismatch / malformed input.
     *
     * No gpg call required -- only hash and compare. The server never needs the
     * original token plaintext after issue() returns.
     *
     * Anti-replay is the caller's responsibility: drop $pending from storage
     * after success so a second verify finds nothing to verify against.
     */
    public function verify($pending, $response)
    {
        $required = array('fingerprint', 'token_hash', 'expires_at');
        foreach ($required as $key) {
            if (empty($pending[$key])) {
                throw new PgploginException("Pending challenge is missing field: {$key}");
            }
        }

        if (time() >= (int) $pending['expires_at']) {
            throw new PgploginException('Challenge expired. Request a new one.');
        }

        $given = $this->normalizeResponse($response);
        if ($given === '') {
            throw new PgploginException('Empty response. Paste the plaintext from `gpg --decrypt`.');
        }

        if (! hash_equals((string) $pending['token_hash'], hash('sha256', $given))) {
            throw new PgploginException(
                'Decrypted value does not match. Make sure you pasted the full plaintext output of `gpg --decrypt`.'
            );
        }

        return (string) $pending['fingerprint'];
    }

    /**
     * Optional helper: peek at a key without issuing a challenge.
     * Returns array('fingerprint' => string, 'can_encrypt' => bool, 'uids' => array<string>).
     */
    public function inspect($armoredPublicKey)
    {
        $armoredPublicKey = $this->normalizeArmored($armoredPublicKey);
        $this->assertLooksLikePublicKey($armoredPublicKey);

        $self = $this;
        return $this->withTempKeyring(function ($home) use ($self, $armoredPublicKey) {
            $imported = $self->runGpg($home, array('--import'), $armoredPublicKey);
            if ($imported['exit'] !== 0) {
                throw new PgploginException('Could not parse OpenPGP public key.');
            }
            $info = $self->listPrimaryKey($home);
            if ($info === null) {
                throw new PgploginException('No usable key found.');
            }
            return $info;
        });
    }

    // ------------------------------------------------------------------
    //  Internals. Made public only so the closures inside issue/inspect
    //  can reach them via $self -- not part of the documented API.
    // ------------------------------------------------------------------

    public function getTtlSeconds()
    {
        return $this->ttlSeconds;
    }

    public function normalizeArmored($armored)
    {
        return str_replace(array("\r\n", "\r"), "\n", trim((string) $armored));
    }

    public function assertLooksLikePublicKey($armored)
    {
        if (strpos($armored, '-----BEGIN PGP PUBLIC KEY BLOCK-----') === false
            || strpos($armored, '-----END PGP PUBLIC KEY BLOCK-----') === false) {
            throw new PgploginException(
                'That does not look like an OpenPGP public key. '
                .'Paste the full output of `gpg --armor --export <your-key>`, '
                .'including the BEGIN/END markers.'
            );
        }
        if (strlen($armored) > 200000) {
            throw new PgploginException('Public key is unreasonably large.');
        }
    }

    public function normalizeResponse($text)
    {
        // The decrypted token is hex only -- strip every whitespace and
        // lowercase, so clipboard wrapping / trailing newlines never matter.
        return strtolower(preg_replace('/\s+/', '', (string) $text));
    }

    /**
     * Parse `gpg --list-keys --with-colons --fixed-list-mode` to extract:
     *   - primary fingerprint
     *   - whether any non-expired/non-revoked subkey (or primary) can encrypt
     *   - uids (informational)
     *
     * Returns null if nothing usable was found.
     */
    public function listPrimaryKey($home)
    {
        $res = $this->runGpg($home, array(
            '--list-keys',
            '--with-colons',
            '--fixed-list-mode',
        ));
        if ($res['exit'] !== 0) {
            return null;
        }

        $primaryFp = null;
        $canEncrypt = false;
        $uids = array();

        $currentBlockUsable = false;
        $currentBlockCanEncrypt = false;
        $currentBlockIsPrimary = false;
        $awaitingFingerprint = false;

        foreach (explode("\n", $res['stdout']) as $line) {
            if ($line === '') {
                continue;
            }
            $f = explode(':', $line);
            $type = isset($f[0]) ? $f[0] : '';

            if ($type === 'pub' || $type === 'sub') {
                $validity = isset($f[1]) ? $f[1] : '';
                $caps     = isset($f[11]) ? $f[11] : '';
                $expires  = isset($f[6]) ? $f[6] : '';

                $expired = ($expires !== '' && ctype_digit($expires) && (int) $expires !== 0 && (int) $expires <= time());
                $revoked = ($validity === 'r');
                $disabled = ($validity === 'd');
                $invalid = ($validity === 'i' || $validity === 'n');

                $currentBlockUsable = ! ($expired || $revoked || $disabled || $invalid);
                $currentBlockCanEncrypt = $currentBlockUsable && (strpos($caps, 'e') !== false);
                $currentBlockIsPrimary = ($type === 'pub');
                $awaitingFingerprint = true;
                continue;
            }

            if ($type === 'fpr' && $awaitingFingerprint) {
                $awaitingFingerprint = false;
                $fp = strtolower(isset($f[9]) ? $f[9] : '');
                if (! preg_match('/^[a-f0-9]{40}$/', $fp)) {
                    if ($currentBlockIsPrimary) {
                        return null;
                    }
                    continue;
                }
                if ($currentBlockIsPrimary && $primaryFp === null) {
                    $primaryFp = $fp;
                }
                if ($currentBlockCanEncrypt) {
                    $canEncrypt = true;
                }
                continue;
            }

            if ($type === 'uid') {
                $uid = isset($f[9]) ? $f[9] : '';
                if ($uid !== '') {
                    $uids[] = $uid;
                }
            }
        }

        if ($primaryFp === null) {
            return null;
        }

        return array(
            'fingerprint' => $primaryFp,
            'can_encrypt' => $canEncrypt,
            'uids' => $uids,
        );
    }

    /**
     * Run gpg with an isolated GNUPGHOME and optional stdin.
     * Returns array('exit' => int, 'stdout' => string, 'stderr' => string).
     */
    public function runGpg($home, array $args, $stdin = '')
    {
        $cmd = array_merge(array(
            $this->gpgBinary,
            '--homedir', $home,
            '--batch',
            '--no-tty',
            '--quiet',
            '--yes',
        ), $args);

        $descriptors = array(
            0 => array('pipe', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),
        );

        $env = array(
            'GNUPGHOME' => $home,
            'LC_ALL'    => 'C',
            'PATH'      => getenv('PATH') ? getenv('PATH') : '/usr/local/bin:/usr/bin:/bin',
        );

        $pipes = array();
        $proc = @proc_open($cmd, $descriptors, $pipes, $home, $env);
        if (! is_resource($proc)) {
            throw new PgploginException(
                "Could not execute `{$this->gpgBinary}`. Is the gpg binary installed and on PATH?"
            );
        }

        if ($stdin !== '') {
            fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);

        $stdout = stream_get_contents($pipes[1]);
        if ($stdout === false) { $stdout = ''; }
        $stderr = stream_get_contents($pipes[2]);
        if ($stderr === false) { $stderr = ''; }
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exit = proc_close($proc);

        return array(
            'exit'   => (int) $exit,
            'stdout' => $stdout,
            'stderr' => $stderr,
        );
    }

    /**
     * Run $fn with a freshly created, isolated GNUPGHOME that is removed
     * unconditionally on return. The host system's keyring is never touched.
     */
    private function withTempKeyring($fn)
    {
        $home = sys_get_temp_dir().DIRECTORY_SEPARATOR.'pgplogin-'.bin2hex(random_bytes(8));
        if (! @mkdir($home, 0700, true) && ! is_dir($home)) {
            throw new PgploginException('Could not create temporary keyring directory.');
        }
        try {
            return $fn($home);
        } finally {
            $this->rrmdir($home);
        }
    }

    private function rrmdir($path)
    {
        if (! is_dir($path)) {
            return;
        }
        $items = scandir($path);
        if ($items === false) {
            $items = array();
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $full = $path.DIRECTORY_SEPARATOR.$item;
            if (is_dir($full) && ! is_link($full)) {
                $this->rrmdir($full);
            } else {
                @unlink($full);
            }
        }
        @rmdir($path);
    }
}

} // class_exists guard
