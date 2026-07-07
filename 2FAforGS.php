<?php if (!defined('IN_GS')) { die('You cannot load this page directly.'); }

/*
Plugin Name: 2FA for GS
Description: Add Two-Factor Authentication (Google Authenticator, Authy or any TOTP app) to admin login page. (SQLite3 required)
Version: 1.0
Author: risingisland
Author URI: https://getsimple-ce.ovh/donate
*/

i18n_merge('2FAforGS') || i18n_merge('2FAforGS', 'en_US');

// ─── Constants ───────────────────────────────────────────────────────────────
define('GS2FA_DB_PATH',	  GSDATAOTHERPATH . 'gs_2fa.db');
define('GS2FA_SLUG',		 basename(__FILE__, '.php'));
define('GS2FA_COOKIE',	   'gs2fa_verified');  // cookie name for 2FA verified state

// ─── Bootstrap ───────────────────────────────────────────────────────────────

register_plugin(
	GS2FA_SLUG,
	'2FA for GS',
	'1.0',
	'risingisland',
	'https://getsimple-ce.ovh/donate',
	'Add Two-Factor Authentication (Google Authenticator, Authy or any TOTP app) to admin login page. (SQLite3 required)',
	'settings',
	'gs2fa_admin_page'
);

add_action('settings-sidebar', 'createSideMenu', array(GS2FA_SLUG, i18n_r('2FAforGS/lang_Menu_Title') . ' <svg style="vertical-align:middle;" width="20" height="20" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#4a7cf7"/><path d="M16 7a5 5 0 0 0-5 5v2H9a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-2v-2a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v2h-6v-2a3 3 0 0 1 3-3zm0 8a2 2 0 1 1 0 4 2 2 0 0 1 0-4z" fill="#fff"/></svg>', '?id=' . GS2FA_SLUG));
add_action('admin-pre-header', 'gs2fa_guard');

gs2fa_init_db();

// ─────────────────────────────────────────────────────────────────────────────
// DATABASE
// ─────────────────────────────────────────────────────────────────────────────

function gs2fa_db() {
	static $db = null;
	if ($db === null) {
		$db = new SQLite3(GS2FA_DB_PATH);
		$db->busyTimeout(5000);
		$db->exec('PRAGMA journal_mode=WAL;');
	}
	return $db;
}

function gs2fa_init_db() {
	gs2fa_db()->exec("
		CREATE TABLE IF NOT EXISTS gs2fa_users (
			username   TEXT PRIMARY KEY,
			secret	 TEXT NOT NULL DEFAULT '',
			enrolled   INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
		);
		CREATE TABLE IF NOT EXISTS gs2fa_recovery_codes (
			id		INTEGER PRIMARY KEY AUTOINCREMENT,
			username  TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			used	  INTEGER NOT NULL DEFAULT 0,
			used_at   INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_rc_user ON gs2fa_recovery_codes(username);
	");
}

function gs2fa_get_user($username) {
	$st = gs2fa_db()->prepare('SELECT * FROM gs2fa_users WHERE username = :u');
	$st->bindValue(':u', $username, SQLITE3_TEXT);
	$r = $st->execute();
	return $r ? ($r->fetchArray(SQLITE3_ASSOC) ?: false) : false;
}

function gs2fa_upsert_user($username, $secret, $enrolled) {
	$st = gs2fa_db()->prepare("
		INSERT INTO gs2fa_users (username, secret, enrolled, updated_at)
		VALUES (:u, :s, :e, strftime('%s','now'))
		ON CONFLICT(username) DO UPDATE SET
			secret = excluded.secret, enrolled = excluded.enrolled,
			updated_at = excluded.updated_at
	");
	$st->bindValue(':u', $username,	  SQLITE3_TEXT);
	$st->bindValue(':s', $secret,		SQLITE3_TEXT);
	$st->bindValue(':e', (int)$enrolled, SQLITE3_INTEGER);
	$st->execute();
}

function gs2fa_save_recovery_codes($username, array $codes) {
	$db = gs2fa_db();
	$d  = $db->prepare('DELETE FROM gs2fa_recovery_codes WHERE username = :u');
	$d->bindValue(':u', $username, SQLITE3_TEXT);
	$d->execute();
	$i = $db->prepare('INSERT INTO gs2fa_recovery_codes (username, code_hash) VALUES (:u, :h)');
	foreach ($codes as $code) {
		$i->bindValue(':u', $username, SQLITE3_TEXT);
		$i->bindValue(':h', password_hash($code, PASSWORD_BCRYPT), SQLITE3_TEXT);
		$i->execute();
		$i->reset();
	}
}

function gs2fa_consume_recovery_code($username, $input) {
	$st = gs2fa_db()->prepare('SELECT id, code_hash FROM gs2fa_recovery_codes WHERE username = :u AND used = 0');
	$st->bindValue(':u', $username, SQLITE3_TEXT);
	$r  = $st->execute();
	while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
		if (password_verify($input, $row['code_hash'])) {
			$u = gs2fa_db()->prepare("UPDATE gs2fa_recovery_codes SET used=1, used_at=strftime('%s','now') WHERE id=:id");
			$u->bindValue(':id', $row['id'], SQLITE3_INTEGER);
			$u->execute();
			return true;
		}
	}
	return false;
}

function gs2fa_count_codes($username) {
	$st = gs2fa_db()->prepare('SELECT COUNT(*) as n FROM gs2fa_recovery_codes WHERE username=:u AND used=0');
	$st->bindValue(':u', $username, SQLITE3_TEXT);
	$r  = $st->execute();
	$row = $r->fetchArray(SQLITE3_ASSOC);
	return (int)($row['n'] ?? 0);
}

function gs2fa_make_codes() {
	$out = [];
	for ($i = 0; $i < 8; $i++) {
		$out[] = strtoupper(implode('-', str_split(bin2hex(random_bytes(4)), 4)));
	}
	return $out;
}

// ─────────────────────────────────────────────────────────────────────────────
// TOTP  (RFC 6238, self-contained)
// ─────────────────────────────────────────────────────────────────────────────

class GS2FA_TOTP {
	const DIGITS = 6, PERIOD = 30, ALGO = 'sha1', WINDOW = 1;

	static function secret()  { return self::b32enc(random_bytes(20)); }

	static function verify($secret, $code, $ts = 0) {
		$code = preg_replace('/\s+/', '', $code);
		$ts   = $ts ?: time();
		$ctr  = (int)floor($ts / self::PERIOD);
		for ($i = -self::WINDOW; $i <= self::WINDOW; $i++) {
			if (hash_equals(self::hotp($secret, $ctr + $i), $code)) return true;
		}
		return false;
	}

	static function hotp($secret, $ctr) {
		$key  = self::b32dec($secret);
		$msg  = pack('N*', 0) . pack('N*', $ctr);
		$hash = hash_hmac(self::ALGO, $msg, $key, true);
		$off  = ord($hash[strlen($hash)-1]) & 0x0F;
		$num  = (
			((ord($hash[$off])   & 0x7F) << 24) |
			((ord($hash[$off+1]) & 0xFF) << 16) |
			((ord($hash[$off+2]) & 0xFF) << 8)  |
			 (ord($hash[$off+3]) & 0xFF)
		) % (10 ** self::DIGITS);
		return str_pad((string)$num, self::DIGITS, '0', STR_PAD_LEFT);
	}

	static function uri($secret, $account, $issuer) {
		return sprintf('otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			rawurlencode($issuer), rawurlencode($account),
			$secret, rawurlencode($issuer), self::DIGITS, self::PERIOD);
	}

	static function b32enc($data) {
		$a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$o = ''; $v = 0; $b = 0;
		for ($i = 0; $i < strlen($data); $i++) {
			$v = ($v << 8) | ord($data[$i]); $b += 8;
			while ($b >= 5) { $b -= 5; $o .= $a[($v >> $b) & 0x1F]; }
		}
		if ($b) $o .= $a[($v << (5-$b)) & 0x1F];
		return $o;
	}

	static function b32dec($data) {
		$a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$data = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $data));
		$o = ''; $v = 0; $b = 0;
		for ($i = 0; $i < strlen($data); $i++) {
			$v = ($v << 5) | strpos($a, $data[$i]); $b += 5;
			if ($b >= 8) { $b -= 8; $o .= chr(($v >> $b) & 0xFF); }
		}
		return $o;
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// admin-header guard — runs on every admin page and serve the 2FA challenge as a complete page.
// ─────────────────────────────────────────────────────────────────────────────

function gs2fa_is_verified() {
	return !empty($_COOKIE[GS2FA_COOKIE]);
}

function gs2fa_set_verified() {
	// Session cookie (no expiry date) — browser discards it when closed.
	//setcookie(GS2FA_COOKIE, '1', 0, '/', '', false, true); // 0 = session cookie, deleted when browser closes
	setcookie(GS2FA_COOKIE, '1', time() + 10800, '/', '', false, true); // 3 hours
	$_COOKIE[GS2FA_COOKIE] = '1'; // make it available in current request too
}

function gs2fa_clear_verified() {
	// Must match set_verified() params exactly — same path, domain, secure, httponly
	setcookie(GS2FA_COOKIE, '', time() - 3600, '/', '', false, true);
	unset($_COOKIE[GS2FA_COOKIE]);
}

function gs2fa_guard() {
	global $USR;
	if (empty($USR)) return;

	// Already passed 2FA — cookie is present
	if (gs2fa_is_verified()) return;

	$user = gs2fa_get_user($USR);
	if (!$user || !$user['enrolled']) return;  // not enrolled — let through

	// Handle challenge POST
	if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['gs2fa_challenge'])) {
		$input = trim($_POST['gs2fa_code'] ?? '');
		$mode  = $_POST['gs2fa_mode'] ?? 'totp';
		$valid = ($mode === 'recovery')
			? gs2fa_consume_recovery_code($USR, $input)
			: GS2FA_TOTP::verify($user['secret'], $input);

		if ($valid) {
			gs2fa_set_verified();
			global $SITEURL;
			$dest = !empty($_POST['gs2fa_redirect']) ? $_POST['gs2fa_redirect'] : $SITEURL . 'admin/pages.php';
			header('Location: ' . $dest);
			exit;
		}

		// Wrong code — show challenge again with error
		gs2fa_render_challenge($USR, i18n_r('2FAforGS/lang_Invalid_code'));
		exit;
	}

	// Not verified, not a challenge POST — show challenge page
	gs2fa_render_challenge($USR);
	exit;
}

function gs2fa_do_challenge($username, $user) {
	$input = trim($_POST['gs2fa_code'] ?? '');
	$mode  = $_POST['gs2fa_mode'] ?? 'totp';
	$valid = ($mode === 'recovery')
		? gs2fa_consume_recovery_code($username, $input)
		: GS2FA_TOTP::verify($user['secret'], $input);

	if ($valid) {
		gs2fa_set_verified();
		header('Location: ' . ($_POST['gs2fa_redirect'] ?? GSADMIN . 'index.php'));
		exit;
	}
	gs2fa_render_challenge($username, i18n_r('2FAforGS/lang_Invalid_code'));
	exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// CHALLENGE PAGE  (standalone, outside GS chrome)
// ─────────────────────────────────────────────────────────────────────────────

function gs2fa_render_challenge($username, $error = '') {
	$remaining = gs2fa_count_codes($username);
	// Capture the originally-requested URL as the post-verification destination
	global $SITEURL;
	$redirect  = htmlspecialchars($_SERVER['REQUEST_URI'] ?? $SITEURL . 'admin/pages.php');
	$errHtml   = $error ? '<div class="box error">' . htmlspecialchars($error) . '</div>' : '';

	gs2fa_shell(i18n_r('2FAforGS/lang_Verify'), '
<h1>' . i18n_r('2FAforGS/lang_Two_Factor') . '</h1>
<p class="sub">' . i18n_r('2FAforGS/lang_Signed_in') . ' <strong>' . htmlspecialchars($username) . '</strong>. ' . i18n_r('2FAforGS/lang_Enter_your') . '</p>
' . $errHtml . '
<form method="post" action="' . $redirect . '" onsubmit="prep()">
	<input type="hidden" name="gs2fa_challenge" value="1">
	<input type="hidden" name="gs2fa_redirect"  value="' . $redirect . '">
	<input type="hidden" name="gs2fa_mode"	  id="mode" value="totp">
	<input type="hidden" name="gs2fa_code"	  id="final">

	<div class="tabs">
		<button type="button" class="tab active" data-tab="totp"	 onclick="sw(\'totp\')">' . i18n_r('2FAforGS/lang_Authenticator_App') . '</button>
		<button type="button" class="tab"		data-tab="recovery" onclick="sw(\'recovery\')">' . i18n_r('2FAforGS/lang_Recovery_Code') . '</button>
	</div>

	<div class="panel active" id="panel-totp">
		<label>' . i18n_r('2FAforGS/lang_6_digit_code') . '</label>
		<input type="tel" id="tin" maxlength="6" placeholder="000000" autofocus inputmode="numeric" autocomplete="one-time-code">
	</div>
	<div class="panel" id="panel-recovery">
		<label>' . i18n_r('2FAforGS/lang_Recovery_Code') . '</label>
		<input type="text" id="rin" maxlength="9" placeholder="XXXX-XXXX" autocomplete="off">
		<p class="hint">' . (int)$remaining . ' ' .i18n_r('2FAforGS/lang_code_remaining') . '</p>
	</div>

	<button type="submit" class="btn">' . i18n_r('2FAforGS/lang_Verify_Continue') . '</button>
</form>
<script>
function sw(t){
	document.querySelectorAll(".tab").forEach(function(e){e.classList.remove("active")});
	document.querySelectorAll(".panel").forEach(function(e){e.classList.remove("active")});
	document.querySelector(".tab[data-tab=\'"+t+"\']").classList.add("active");
	document.getElementById("panel-"+t).classList.add("active");
	document.getElementById("mode").value=t;
}
function prep(){
	var m=document.getElementById("mode").value;
	document.getElementById("final").value=(m==="recovery")
		?document.getElementById("rin").value
		:document.getElementById("tin").value;
}
</script>');
}

// ─────────────────────────────────────────────────────────────────────────────
// STANDALONE PAGE SHELL  (challenge page only — no GS chrome)
// ─────────────────────────────────────────────────────────────────────────────

function gs2fa_shell($title, $body) {
	echo '<!DOCTYPE html><html lang="en">
	<head>
		<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
		<title>' . $title . '</title>
		<style>
			*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
			body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f2f5; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px}
			.card{background:#fff; border-radius:10px;box-shadow:0 2px 16px rgba(0,0,0,.1); padding:36px 40px;width:100%;max-width:420px}
			.logo{display:flex;align-items:center;gap:10px;margin-bottom:24px}
			.logo-text{font-size:1rem;font-weight:600;color:#111;line-height:1.2}
			.logo-text small{display:block;font-size:.72rem;font-weight:400;color:#888}
			h1{font-size:1.2rem;font-weight:700;color:#111;margin-bottom:5px}
			p.sub{font-size:.85rem;color:#555;margin-bottom:20px;line-height:1.5}
			label{display:block;font-size:.78rem;font-weight:600;color:#333;margin-bottom:4px;margin-top:14px}
			input[type=text],input[type=tel]{width:100%;padding:9px 12px;border:1.5px solid #d0d5dd;border-radius:6px;font-size:1.1rem;letter-spacing:.12em;text-align:center;outline:none}
			input:focus{border-color:#4a7cf7;box-shadow:0 0 0 3px rgba(74,124,247,.15)}
			.btn{display:block;width:100%; margin-top:20px; padding:10px; background:#4a7cf7; color:#fff; border:none; border-radius:6px; font-size:.92rem; font-weight:600; cursor:pointer}
			.btn:hover{background:#3a6ae0}
			.box{padding:9px 12px;border-radius:6px;font-size:.83rem;margin-bottom:14px}
			.error{background:#fff0f0;border:1px solid #fca5a5;color:#b91c1c}
			.tabs{display:flex;border:1.5px solid #d0d5dd;border-radius:6px;overflow:hidden;margin-bottom:16px}
			.tab{flex:1;padding:7px; text-align:center; font-size:.8rem; font-weight:600; cursor:pointer; background:#fff; color:#555;border:none}
			.tab.active{background:#4a7cf7;color:#fff}
			.panel{display:none}.panel.active{display:block}
			.hint{font-size:.75rem;color:#999;margin-top:6px;text-align:center}
		</style>
	</head>
	<body>
		<div class="card">
			<div class="logo">
				<svg width="30" height="30" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#4a7cf7"/><path d="M16 7a5 5 0 0 0-5 5v2H9a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-2v-2a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v2h-6v-2a3 3 0 0 1 3-3zm0 8a2 2 0 1 1 0 4 2 2 0 0 1 0-4z" fill="#fff"/></svg>
				<div class="logo-text">' . (!empty($GLOBALS['SITENAME']) ? htmlspecialchars($GLOBALS['SITENAME']) : 'GetSimple CMS') . ' <small>' . i18n_r('2FAforGS/lang_Page_Title') . '</small></div>
			</div>
			' . $body . '
		</div>
	</body>
</html>';
}

// ── Shared admin styles — called at the top of every admin step ──────────────

function gs2fa_admin_styles() {
	echo '
	<style>
		.g-wrap{max-width:940px;margin:20px 0}
		.g-wrap h3{font-size:1.1rem;font-weight:700;margin-bottom:16px}
		.g-wrap header p{color:grey;}
		.g-wrap header hr{margin:10px 0 30px;border: 0;border-top: 1px dotted #8c8c8c;border-bottom: 1px dotted #fff;}
		.g-row{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid #f0f0f0}
		.g-row:last-child{border-bottom:none}
		.g-lbl strong{display:block;color:#111;margin-bottom:2px;font-size:.88rem}
		.g-lbl small{color:#888;font-size:.77rem}
		.g-badge{display:inline-block;padding:3px 12px;border-radius:20px;font-size:.78rem;font-weight:700}
		.g-on{background:#d1fae5;color:#065f46}.g-off{background:#fee2e2;color:#991b1b}
		.g-notice{padding:12px 16px;border-radius:6px;margin-bottom:16px;font-size:.86rem;line-height:1.7;word-break:break-all}
		.g-info{background:#eff6ff;border:1px solid #bfdbfe;color:#1e40af}
		.g-warn{background:#fffbeb;border:1px solid #fcd34d;color:#92400e}
		.g-code{font-family:monospace;font-size:.8rem;background:#f3f4f6;padding:2px 6px;border-radius:4px;margin:2px;display:inline-block}
		.g-btn{padding:7px 16px; border-radius:5px; font-size:.82rem; font-weight:600; cursor:pointer; border:none; text-decoration:none; display:inline-block}
		.g-btn-primary{background:#4a7cf7;color:#fff!important;text-decoration:none!important}
		.g-btn-primary:hover{background:#3a6ae0}
		.g-btn-success{background:#059669;color:#fff!important;text-decoration:none!important}
		.g-btn-success:hover{background:#047857}
		.g-btn-danger{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}
		.g-btn-danger:hover{background:#fecaca} .g-qr{text-align:center;margin:16px 0}
		.g-qr img{border:1px solid #e5e7eb;border-radius:6px;padding:6px;max-width:180px}
		.g-secret{background:#f8f9fa;border:1px solid #e5e7eb; border-radius:6px; padding:10px; font-family:monospace; font-size:.9rem; word-break:break-all; text-align:center; color:#333; margin-bottom:14px}
		.g-step{font-size:.8rem;color:#888;margin-bottom:10px}.g-step strong{color:#444}
		.g-codes-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:14px 0}
		.g-recovery-code{background:#f8f9fa;border:1px solid #e5e7eb;border-radius:5px;padding:7px 6px;font-family:monospace;font-size:.82rem;text-align:center}
		.g-info-box{background:#f0f6ff;border:1px solid #bfdbfe;color:#1d4ed8;padding:10px 13px;border-radius:6px;font-size:.84rem;margin-bottom:14px;line-height:1.5}
		.g-warn-box{background:#fffbeb;border:1px solid #fcd34d;color:#92400e;padding:10px 13px;border-radius:6px;font-size:.84rem;margin-bottom:14px}
		.g-err-box{background:#fff0f0;border:1px solid #fca5a5;color:#b91c1c;padding:10px 13px;border-radius:6px;font-size:.84rem;margin-bottom:14px}
	</style>';
}

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN PAGE  (rendered inside GS chrome by GS itself via 8th param)
// ─────────────────────────────────────────────────────────────────────────────

function gs2fa_admin_page() {
	global $USR;
	$username = $USR ?? '';

	if (!$username) {
		echo '<p style="color:red">' . i18n_r('2FAforGS/lang_Could_not') . '</p>';
		return;
	}

	$user	 = gs2fa_get_user($username);
	$enrolled = $user && $user['enrolled'];

	// ── Step router ──────────────────────────────────────────────────────────
	// gs2fa_challenge=1 → 2FA challenge after login (POST to verify, GET to show form)
	// gs2fa_step=qr	 → enrollment QR + confirm form
	// gs2fa_step=codes  → handle confirm POST, show recovery codes
	// (default)		 → main status page

	// ── Challenge step (post-login 2FA prompt) ───────────────────────────────
	if (isset($_GET['gs2fa_challenge'])) {
		// During the post-login challenge, $USR may not be set yet.
		// Fall back to the pending user stored in session by gs2fa_post_login().
		if (empty($username)) {
			$username = $_SESSION['gs2fa_pending_user'] ?? '';
		}
		if (empty($username)) {
			echo '<p style="color:red">' . i18n_r('2FAforGS/lang_Session_expired') . '</p>';
			return;
		}
		// Re-fetch user record in case $user was resolved from an empty $username above
		if (!$user || !$user['enrolled']) {
			$user = gs2fa_get_user($username);
		}

		if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['gs2fa_challenge_submit'])) {
			$input = trim($_POST['gs2fa_code'] ?? '');
			$mode  = $_POST['gs2fa_mode'] ?? 'totp';
			$valid = ($mode === 'recovery')
				? gs2fa_consume_recovery_code($username, $input)
				: GS2FA_TOTP::verify($user['secret'], $input);

			if ($valid) {
				gs2fa_set_verified();
				
				global $SITEURL;
				// Redirect to dashboard or pages depending on what GS would normally do
				$dest = file_exists(GSPLUGINPATH . 'Dashboard.php') ? 'load.php?id=Dashboard' : 'pages.php';
				header('Location: ' . $SITEURL . 'admin/' . $dest);
				exit;
			}
			gs2fa_admin_step_challenge($username, i18n_r('2FAforGS/lang_Invalid_code'));
		} else {
			gs2fa_admin_step_challenge($username);
		}
		return;
	}

	$step = $_GET['gs2fa_step'] ?? '';

	// Handle confirmation POST (step=codes means we just confirmed the code)
	if ($step === 'codes' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['gs2fa_secret'])) {
		$secret = $_POST['gs2fa_secret'] ?? '';
		$code   = trim($_POST['gs2fa_confirm_code'] ?? '');

		if (!GS2FA_TOTP::verify($secret, $code)) {
			// Code wrong — go back to QR step with error
			gs2fa_admin_step_qr($username, i18n_r('2FAforGS/lang_Code_not_match'), $secret);
			return;
		}

		// Valid — save and show recovery codes
		gs2fa_upsert_user($username, $secret, true);
		$codes = gs2fa_make_codes();
		gs2fa_save_recovery_codes($username, $codes);
		gs2fa_set_verified();  // mark verified via cookie after enrollment
		gs2fa_admin_step_codes($username, $codes);
		return;
	}

	if ($step === 'qr') {
		gs2fa_admin_step_qr($username);
		return;
	}

	// ── Main status page ─────────────────────────────────────────────────────
	$msg = '';

	if (isset($_POST['gs2fa_reset'])) {
		gs2fa_upsert_user($username, '', false);
		gs2fa_clear_verified();
		$enrolled = false;
		$user	 = false;
		$msg = '<div class="g-notice g-warn">' . i18n_r('2FAforGS/lang_2FA_reset') . '</div>';
	}

	if (isset($_POST['gs2fa_regen']) && $enrolled) {
		$codes = gs2fa_make_codes();
		gs2fa_save_recovery_codes($username, $codes);
		$cd = '';
		foreach ($codes as $c) $cd .= '<span class="g-code">' . htmlspecialchars($c) . '</span> ';
		$msg = '<div class="g-notice g-info"><strong>' . i18n_r('2FAforGS/lang_New_codes') . ':</strong><br><br>' . $cd . '</div>';
	}

	$remaining = $enrolled ? gs2fa_count_codes($username) : 0;
	$badge	 = $enrolled
		? '<span class="g-badge g-on">&#10004; ' . i18n_r('2FAforGS/lang_Enabled') . '</span>'
		: '<span class="g-badge g-off">&#10008; ' . i18n_r('2FAforGS/lang_Not_Enrolled') . '</span>';

	gs2fa_admin_styles();
	echo '
<div class="g-wrap">
<header>
<h3>' . i18n_r('2FAforGS/lang_Page_Title') . ' <svg style="vertical-align:middle;" width="1.2em" height="1.2em" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#4a7cf7"/><path d="M16 7a5 5 0 0 0-5 5v2H9a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-2v-2a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v2h-6v-2a3 3 0 0 1 3-3zm0 8a2 2 0 1 1 0 4 2 2 0 0 1 0-4z" fill="#fff"/></svg></h3>
<p>' . i18n_r('2FAforGS/lang_Description') . '</p>
<hr>
</header>
' . $msg . '
<div class="g-row">
	<div class="g-lbl"><strong>' . i18n_r('2FAforGS/lang_Status') . '</strong><small>' . i18n_r('2FAforGS/lang_User') . ': ' . htmlspecialchars($username) . '</small></div>
  ' . $badge . '
</div>';

	if ($enrolled) {
		echo '
<div class="g-row">
	<div class="g-lbl"><strong>' . i18n_r('2FAforGS/lang_Recovery_codes') . '</strong><small>' . (int)$remaining . ' ' . i18n_r('2FAforGS/lang_of_8_unused') . '</small></div>
	<form method="post" style="display:inline">
		<button name="gs2fa_regen" value="1" class="g-btn g-btn-primary" onclick="return confirm(\' ' . i18n_r('2FAforGS/lang_Regenerate_all') . ' \')">' . i18n_r('2FAforGS/lang_Regenerate_Codes') . '</button>
	</form>
</div>
<div class="g-row">
	<div class="g-lbl"><strong>' . i18n_r('2FAforGS/lang_Reset_Re_enroll') . '</strong><small>' . i18n_r('2FAforGS/lang_Clears_secret') . '</small></div>
	<form method="post" style="display:inline">
		<button name="gs2fa_reset" value="1" class="g-btn g-btn-danger" onclick="return confirm(\' ' . i18n_r('2FAforGS/lang_must_re_enroll') . ' \')">' . i18n_r('2FAforGS/lang_Reset_2FA') . '</button>
	</form>
</div>';
	} else {
		echo '
<div class="g-row">
	<div class="g-lbl"><strong>' . i18n_r('2FAforGS/lang_Enroll') . '</strong><small>' . i18n_r('2FAforGS/lang_Scan_QR') . '</small></div>
	<a href="load.php?id=' . GS2FA_SLUG . '&gs2fa_step=qr" class="g-btn g-btn-success">' . i18n_r('2FAforGS/lang_Enroll_Now') . ' &rarr;</a>
</div>';
	}

	echo '</div>';
}

// ── Step: QR code + confirmation form ────────────────────────────────────────

function gs2fa_admin_step_qr($username, $error = '', $existingSecret = '') {
	gs2fa_admin_styles();
	echo '<div class="g-wrap">';
	$secret  = $existingSecret ?: GS2FA_TOTP::secret();
	global $SITENAME;
	$issuer  = !empty($SITENAME) ? $SITENAME : 'GetSimple CMS CE';
	$uri	 = GS2FA_TOTP::uri($secret, $username, $issuer);
	$qrUrl   = 'https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=' . rawurlencode($uri);
	$errHtml = $error ? '<div class="g-err-box">' . htmlspecialchars($error) . '</div>' : '';

	echo '
<header>
<h3>' . i18n_r('2FAforGS/lang_Enroll_Two_Factor') . ' <svg style="vertical-align:middle;" width="1.2em" height="1.2em" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#4a7cf7"/><path d="M16 7a5 5 0 0 0-5 5v2H9a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-2v-2a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v2h-6v-2a3 3 0 0 1 3-3zm0 8a2 2 0 1 1 0 4 2 2 0 0 1 0-4z" fill="#fff"/></svg></h3>
<hr>
</header>
' . $errHtml . '
<div class="g-info-box">&#128241; ' . i18n_r('2FAforGS/lang_Works_Google') . '</div>

<div class="g-step"><strong>' . i18n_r('2FAforGS/lang_Step_1') . '</div>
<div class="g-qr"><img src="' . htmlspecialchars($qrUrl) . '" width="180" height="180" alt="QR Code"></div>

<div class="g-step">' . i18n_r('2FAforGS/lang_Step_2') . ':</div>
<div class="g-secret">' . htmlspecialchars($secret) . '</div>

<form method="post" action="load.php?id=' . GS2FA_SLUG . '&gs2fa_step=codes">
	<input type="hidden" name="gs2fa_secret" value="' . htmlspecialchars($secret) . '">
	<div class="g-row">
		<div class="g-lbl">
			<strong>' . i18n_r('2FAforGS/lang_Step_3') . '</strong>
			<small>' . i18n_r('2FAforGS/lang_Enter_6_digit') . '</small>
		</div>
		<input type="tel" name="gs2fa_confirm_code" maxlength="6" placeholder="000000" inputmode="numeric" autofocus autocomplete="off" style="width:120px; padding:7px 10px; border:2px solid #CF3805; border-radius:5px; font-size:1.05rem; letter-spacing:.12em; text-align:center; outline:none;">
	</div>
	<div style="display:flex;gap:10px;margin-top:6px;align-items:center">
		<button type="submit" class="g-btn g-btn-success">' . i18n_r('2FAforGS/lang_Confirm_Enable') . '</button>
		<a href="load.php?id=' . GS2FA_SLUG . '" class="g-btn g-btn-danger" style="border:none">' . i18n_r('2FAforGS/lang_Cancel') . '</a>
	</div>
</form>
</div>';
}

// ── Step: recovery codes display ─────────────────────────────────────────────

function gs2fa_admin_step_codes($username, array $codes) {
	gs2fa_admin_styles();
	$grid = '';
	foreach ($codes as $c) {
		$grid .= '<div class="g-recovery-code">' . htmlspecialchars($c) . '</div>';
	}

	echo '
<div class="g-wrap">
	<h3>&#10004; ' . i18n_r('2FAforGS/lang_2FA_Enabled') . ' <svg style="vertical-align:middle;" width="1.2em" height="1.2em" viewBox="0 0 32 32" fill="none"><rect width="32" height="32" rx="8" fill="#4a7cf7"/><path d="M16 7a5 5 0 0 0-5 5v2H9a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2h-2v-2a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v2h-6v-2a3 3 0 0 1 3-3zm0 8a2 2 0 1 1 0 4 2 2 0 0 1 0-4z" fill="#fff"/></svg></h3>
	<div class="g-info-box">' . i18n_r('2FAforGS/lang_Two_factor_auth') . ' <strong>' . htmlspecialchars($username) . '</strong>.</div>
	<div class="g-warn-box">&#9888;&#65039; ' . i18n_r('2FAforGS/lang_8_single_use') . '</div>
	<div class="g-codes-grid">' . $grid . '</div>
	<a href="load.php?id=' . GS2FA_SLUG . '" class="g-btn g-btn-primary" style="margin-top:16px;display:inline-block">' . i18n_r('2FAforGS/lang_saved_my_codes') . '</a>
</div>';
}

// ── Step: 2FA challenge (rendered inside GS chrome after login redirect) ─────

function gs2fa_admin_step_challenge($username, $error = '') {
	$remaining = gs2fa_count_codes($username);
	$errHtml   = $error ? '<div class="g-err-box">' . htmlspecialchars($error) . '</div>' : '';
	$self	  = 'load.php?id=' . GS2FA_SLUG . '&gs2fa_challenge=1';

	echo '
<style>
	.g-challenge{max-width:420px;margin:20px 0}
	.g-challenge h3{font-size:1.1rem;font-weight:700;margin-bottom:8px}
	.g-challenge p.sub{font-size:.86rem;color:#555;margin-bottom:20px;line-height:1.5}
	.g-tabs{display:flex;border:1.5px solid #d0d5dd;border-radius:6px;overflow:hidden;margin-bottom:18px}
	.g-tab{flex:1;padding:8px;text-align:center; font-size:.8rem; font-weight:600; cursor:pointer; background:#fff;color:#555; border:none}
	.g-tab.active{background:#4a7cf7;color:#fff}
	.g-panel{display:none}.g-panel.active{display:block}
	.g-challenge label{display:block;font-size:.78rem;font-weight:600;color:#333;margin-bottom:5px}
	.g-challenge input[type=tel],.g-challenge input[type=text]{width:100%; max-width:220px; padding:9px 12px; border:1.5px solid #d0d5dd;border-radius:6px; font-size:1.15rem; letter-spacing:.12em; text-align:center; outline:none}
	.g-challenge input:focus{border-color:#4a7cf7;box-shadow:0 0 0 3px rgba(74,124,247,.15)}
	.g-hint{font-size:.75rem;color:#999;margin-top:6px}
	.g-err-box{background:#fff0f0; border:1px solid #fca5a5;color:#b91c1c; padding:9px 12px; border-radius:6px; font-size:.83rem; margin-bottom:14px}
</style>

<div class="g-challenge">
	<h3>&#128274; Two-Factor Verification</h3>
	<p class="sub">Signed in as <strong>' . htmlspecialchars($username) . '</strong>. Enter your authenticator code to continue.</p>
	' . $errHtml . '
	<form method="post" action="' . $self . '" onsubmit="gs2fa_prep()">
		<input type="hidden" name="gs2fa_challenge_submit" value="1">
		<input type="hidden" name="gs2fa_mode" id="gs2fa_mode" value="totp">
		<input type="hidden" name="gs2fa_code" id="gs2fa_final">

		<div class="g-tabs">
			<button type="button" class="g-tab active" data-tab="totp"	 onclick="gs2fa_sw(\'totp\')">Authenticator App</button>
			<button type="button" class="g-tab"		data-tab="recovery" onclick="gs2fa_sw(\'recovery\')">Recovery Code</button>
		</div>

		<div class="g-panel active" id="gs2fa-panel-totp">
			<label>6-digit code</label>
			<input type="tel" id="gs2fa_tin" maxlength="6" placeholder="000000"
			   autofocus inputmode="numeric" autocomplete="one-time-code">
		</div>
		<div class="g-panel" id="gs2fa-panel-recovery">
			<label>Recovery code</label>
			<input type="text" id="gs2fa_rin" maxlength="9" placeholder="XXXX-XXXX" autocomplete="off">
			<p class="g-hint">' . (int)$remaining . ' recovery code(s) remaining</p>
		</div>

		<button type="submit" class="g-btn g-btn-primary" style="margin-top:18px">Verify &amp; Continue</button>
	</form>
</div>

<script>
function gs2fa_sw(t){
	document.querySelectorAll(".g-tab").forEach(function(e){e.classList.remove("active");});
	document.querySelectorAll(".g-panel").forEach(function(e){e.classList.remove("active");});
	document.querySelector(".g-tab[data-tab=\'"+t+"\']").classList.add("active");
	document.getElementById("gs2fa-panel-"+t).classList.add("active");
	document.getElementById("gs2fa_mode").value=t;
}
function gs2fa_prep(){
	var m=document.getElementById("gs2fa_mode").value;
	document.getElementById("gs2fa_final").value=
		(m==="recovery")
		? document.getElementById("gs2fa_rin").value
		: document.getElementById("gs2fa_tin").value;
}
</script>';
}