<?php

/**
 * pgplogin · vanilla-PHP demo
 *
 * Run from the repo root:
 *     php -S 127.0.0.1:8000 -t example
 * Or:
 *     docker compose up --build
 *
 * Then open http://127.0.0.1:8000
 *
 * The whole demo is this one file plus `pgplogin.php` next to it. The pending
 * challenge lives in $_SESSION — see the line marked "▶ storage" to swap to
 * Redis, a database, or anything else.
 */

require_once __DIR__.'/../pgplogin.php';

session_name('PGPDEMO');
session_start();

$auth = new Pgplogin();

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$error = null;
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

function redirect(string $to): never
{
    header('Location: '.$to);
    exit;
}

function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

try {
    switch (true) {

        case $path === '/login' && $method === 'POST':
            $pubkey = (string) ($_POST['public_key'] ?? '');
            if (strlen($pubkey) < 50) {
                $error = 'Paste your public key first.';
                $action = 'home';
                break;
            }
            // ▶ storage: anywhere durable across the two requests is fine.
            $_SESSION['pgp_pending'] = $auth->issue($pubkey);
            redirect('/challenge');

        case $path === '/challenge' && $method === 'GET':
            if (empty($_SESSION['pgp_pending'])) {
                redirect('/');
            }
            if (time() >= (int) $_SESSION['pgp_pending']['expires_at']) {
                unset($_SESSION['pgp_pending']);
                $error = 'Challenge expired. Request a new one.';
                $action = 'home';
                break;
            }
            $action = 'challenge';
            break;

        case $path === '/challenge' && $method === 'POST':
            if (empty($_SESSION['pgp_pending'])) {
                redirect('/');
            }
            $response = (string) ($_POST['response'] ?? '');
            try {
                $fp = $auth->verify($_SESSION['pgp_pending'], $response);
            } catch (PgploginException $e) {
                $error = $e->getMessage();
                $action = 'challenge';
                break;
            }

            // anti-replay: drop the pending struct from storage
            unset($_SESSION['pgp_pending']);
            session_regenerate_id(true);
            $_SESSION['auth_fingerprint'] = $fp;
            redirect('/dashboard');

        case $path === '/dashboard' && $method === 'GET':
            if (empty($_SESSION['auth_fingerprint'])) {
                redirect('/');
            }
            $action = 'dashboard';
            break;

        case $path === '/logout' && $method === 'POST':
            $_SESSION = ['flash' => 'Signed out.'];
            session_regenerate_id(true);
            redirect('/');

        case $path === '/' && $method === 'GET':
            if (! empty($_SESSION['auth_fingerprint'])) {
                redirect('/dashboard');
            }
            $action = 'home';
            break;

        default:
            http_response_code(404);
            $action = '404';
    }
} catch (PgploginException $e) {
    $error = $e->getMessage();
    $action = 'home';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>pgplogin</title>
<style>
  body { margin: 0; background: #fff; color: #000; line-height: 1.5; }
  main { max-width: 720px; margin: 2em auto; padding: 0 1em; }
  header.site, footer.site { max-width: 720px; margin: 0 auto; padding: 1em; }
  footer.site { border-top: 1px solid #ccc; margin-top: 4em; font-size: 0.85em; color: #666; display: flex; justify-content: space-between; }
  nav.site { float: right; }
  nav.site a, nav.site form { margin-left: 1em; }
  nav.site form { display: inline; }
  h1 { font-size: 2em; }
  h1, h2, h3 { line-height: 1.2; }
  a { color: #00e; }
  a:visited { color: #551A8B; }
  pre, code { background: #f0f0f0; }
  pre { padding: 0.5em; border: 1px solid #ccc; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  textarea { width: 100%; box-sizing: border-box; resize: vertical; }
  input[type="text"] { width: 100%; box-sizing: border-box; }
  button, input[type="submit"] { cursor: pointer; font: inherit; }
  .err-banner { padding: 0.75em 1em; margin: 1em 0; border: 2px solid #c00; color: #800; background: #fee; }
  .ok-banner  { padding: 0.75em 1em; margin: 1em 0; border: 2px solid #080; color: #040; background: #efe; }
  .note { border-left: 3px solid #ccc; padding-left: 1em; color: #555; font-size: 0.9em; margin-top: 3em; }
  .meta-row { display: flex; justify-content: space-between; align-items: baseline; margin: 0.5em 0 1em; color: #555; font-size: 0.9em; }
  details { margin: 1.5em 0; }
  summary { cursor: pointer; }
  .form-actions { display: flex; gap: 1em; align-items: center; margin-top: 1em; }
</style>
</head>
<body>

<header class="site">
  <a href="/"><strong>pgplogin</strong></a> &middot; simple OpenPGP login, decryption flow
  <nav class="site">
    <?php if (! empty($_SESSION['auth_fingerprint'])): ?>
      <a href="/dashboard">dashboard</a>
      <form method="post" action="/logout"><button type="submit">sign out</button></form>
    <?php endif; ?>
  </nav>
</header>

<main>

<?php if ($flash): ?>
  <div class="ok-banner"><?= e($flash) ?></div>
<?php endif; ?>

<?php if ($error): ?>
  <div class="err-banner"><?= e($error) ?></div>
<?php endif; ?>

<?php if ($action === 'home'): ?>

  <h1>Sign in with an OpenPGP key.</h1>
  <p>Paste your public key. The server encrypts a short random token to it and shows you the ciphertext. Decrypt it locally with your private key and paste the plaintext back. That proves you hold the key.</p>

<pre>server  --[ ciphertext ]--&gt;  you
you     --[ plaintext  ]--&gt;  server</pre>

  <p>The server only stores the SHA-256 of the token. The cleartext never lands on disk.</p>

  <form method="post" action="/login">
    <p><label for="public_key">Public key:</label></p>
    <textarea id="public_key" name="public_key" rows="10" placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;...&#10;-----END PGP PUBLIC KEY BLOCK-----" required></textarea>
    <p><small>Export with <code>gpg --armor --export YOUR_EMAIL</code>.</small></p>
    <p><button type="submit">Request challenge</button></p>
  </form>

  <details>
    <summary>No key? Generate a throwaway one.</summary>
<pre>export GNUPGHOME=$(mktemp -d) &amp;&amp; chmod 700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase "" \
    --quick-generate-key "demo &lt;demo@example.com&gt;" default default 1y
gpg --armor --export demo</pre>
  </details>

<?php elseif ($action === 'challenge'):
  $p = $_SESSION['pgp_pending'];
  $secondsLeft = max(0, (int) $p['expires_at'] - time());
?>

  <h1>Challenge.</h1>
  <p>Decrypt this with your private key:</p>

<pre><?= e($p['encrypted_token']) ?></pre>

  <p>Paste the plaintext below.</p>

  <div class="meta-row">
    <span>Fingerprint: <code><?= e($p['fingerprint']) ?></code></span>
    <span>Expires in <?= $secondsLeft ?>s</span>
  </div>

  <form method="post" action="/challenge">
    <p><label for="response">Decrypted plaintext:</label></p>
    <input id="response" name="response" type="text" autocomplete="off" autofocus required>
    <div class="form-actions">
      <button type="submit">Verify</button>
      <a href="/">cancel</a>
    </div>
  </form>

  <details>
    <summary>How to decrypt</summary>
<pre># interactive: run gpg, paste the ciphertext, then press Ctrl-D:
gpg --decrypt

# or save the ciphertext to a file, then:
gpg --decrypt /path/to/file

# or pipe from clipboard:
pbpaste | gpg --decrypt   # macOS
xclip -o | gpg --decrypt  # linux</pre>
  </details>

<?php elseif ($action === 'dashboard'): ?>

  <h1>Signed in.</h1>
  <div class="ok-banner">Authenticated as <code><?= e($_SESSION['auth_fingerprint']) ?></code></div>
  <p>The library tells you which key decrypted the challenge. Mapping that fingerprint to a user record &mdash; creating it on first login, attaching profile data, whatever &mdash; is your application's job.</p>

  <form method="post" action="/logout">
    <p><button type="submit">Sign out</button></p>
  </form>

<?php elseif ($action === '404'): ?>

  <h1>Not found.</h1>
  <p><a href="/">Home</a>.</p>

<?php endif; ?>

</main>

<footer class="site">
  <span><strong>pgplogin</strong> &middot; simple pgp login</span>
  <span>MIT</span>
</footer>

</body>
</html>
