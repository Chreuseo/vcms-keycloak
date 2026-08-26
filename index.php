<?php

/*
This file is part of VCMS.

VCMS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

VCMS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with VCMS. If not, see <http://www.gnu.org/licenses/>.
*/

if (is_file('installer.php')) {
    die('Um das VCMS zu nutzen, muss nach der Installation die Datei installer.php entfernt werden.');
}

require_once('custom/systemconfig.php');
require_once('vendor/vcms/initialize.php');


$libDb->connect();
$libCronjobs->executeDueJobs();


// Keycloak integration: keep OAuth2/OIDC flows when keycloak is enabled
if (isset($libConfig->keycloakEnabled) && $libConfig->keycloakEnabled) {
    // Start session early for PKCE/state handling
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    // If the client requested a KC start redirect (pkce flow)
    if (isset($_GET['kc_start']) && $_GET['kc_start'] === '1') {
        $scheme = isset($_SERVER['HTTP_X_FORWARDED_PROTO']) ? $_SERVER['HTTP_X_FORWARDED_PROTO'] : ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
        $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
        $baseDir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
        $basePath = $baseDir === '' ? '/' : $baseDir . '/';
        $redirectUri = $scheme . '://' . $host . $basePath . 'index.php?pid=login';

        $codeVerifier = bin2hex(random_bytes(32));
        $_SESSION['keycloak_pkce_verifier'] = $codeVerifier;
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        $issuer = '';
        if (isset($libConfig->keycloakAllowedIssuers) && is_array($libConfig->keycloakAllowedIssuers) && count($libConfig->keycloakAllowedIssuers) > 0) {
            $issuer = $libConfig->keycloakAllowedIssuers[0];
        }
        $clientId = '';
        if (isset($libConfig->keycloakClientId) && $libConfig->keycloakClientId !== '') {
            $clientId = $libConfig->keycloakClientId;
        } elseif (isset($libConfig->keycloakAllowedAudiences) && is_array($libConfig->keycloakAllowedAudiences) && count($libConfig->keycloakAllowedAudiences) > 0) {
            $clientId = $libConfig->keycloakAllowedAudiences[0];
        }

        if ($issuer === '' || $clientId === '') {
            $libGlobal->errorTexts[] = 'Keycloak ist aktiviert, aber Issuer oder Client-ID sind nicht konfiguriert.';
        } else {
            $authBase = rtrim($issuer, '/') . '/protocol/openid-connect/auth';
            $state = bin2hex(random_bytes(16));
            $_SESSION['keycloak_oauth_state'] = $state;

            $q = http_build_query(array(
                'response_type' => 'code',
                'client_id' => $clientId,
                'redirect_uri' => $redirectUri,
                'scope' => 'openid email profile',
                'code_challenge' => $challenge,
                'code_challenge_method' => 'S256',
                'state' => $state
            ), '', '&', PHP_QUERY_RFC3986);

            header('Location: ' . $authBase . '?' . $q, true, 302);
            exit;
        }
    }

    // Handle token via Authorization header / parameter
    $jwt = null;
    if (isset($_SERVER['HTTP_AUTHORIZATION']) && preg_match('/Bearer\s+(.*)/i', $_SERVER['HTTP_AUTHORIZATION'], $m)) {
        $jwt = trim($m[1]);
    } elseif (isset($_GET['kc_token'])) {
        $jwt = trim($_GET['kc_token']);
    } elseif (isset($_POST['kc_token'])) {
        $jwt = trim($_POST['kc_token']);
    }

    if ($jwt) {
        if (session_status() === PHP_SESSION_NONE) session_start();
        $libAuth = new \vcms\LibAuth();
        if ($libAuth->loginWithKeycloakJwt($jwt)) {
            $_SESSION['libAuth'] = $libAuth;
            $targetPid = isset($_GET['pid']) ? $_GET['pid'] : '';
            if ($targetPid === '' || $targetPid === 'login') {
                $targetPid = 'intranet_home';
            }
            header('Location: index.php?pid=' . urlencode($targetPid));
            exit;
        }
    }

    // Authorization code flow return (PKCE)
    if (isset($_GET['code']) && $_GET['code'] !== '') {
        if (session_status() === PHP_SESSION_NONE) session_start();
        if (isset($_SESSION['keycloak_oauth_state']) && isset($_GET['state']) && hash_equals($_SESSION['keycloak_oauth_state'], $_GET['state'])) {
            unset($_SESSION['keycloak_oauth_state']);
        }

        $scheme = isset($_SERVER['HTTP_X_FORWARDED_PROTO']) ? $_SERVER['HTTP_X_FORWARDED_PROTO'] : ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
        $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
        $baseDir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
        $basePath = $baseDir === '' ? '/' : $baseDir . '/';
        $redirectUri = $scheme . '://' . $host . $basePath . 'index.php?pid=login';

        $libAuth = new \vcms\LibAuth();
        if ($libAuth->loginWithKeycloakAuthCode($_GET['code'], $redirectUri)) {
            if (session_status() === PHP_SESSION_NONE) session_start();
            $_SESSION['libAuth'] = $libAuth;
            $targetPid = isset($_GET['pid']) ? $_GET['pid'] : '';
            if ($targetPid === '' || $targetPid === 'login') {
                $targetPid = 'intranet_home';
            }
            header('Location: index.php?pid=' . urlencode($targetPid));
            exit;
        }
    }
}

// preserve upstream local login behavior: only active when keycloak disabled
if ((!isset($libConfig->keycloakEnabled) || !$libConfig->keycloakEnabled) && isset($_POST['intranet_login_email']) && isset($_POST['intranet_login_password'])) {
    $libAuth = new \vcms\LibAuth();
    $isLoggedIn = $libAuth->login($_POST['intranet_login_email'], $_POST['intranet_login_password']);

    if ($isLoggedIn) {
        if (session_status() === PHP_SESSION_NONE) session_start();
        $_SESSION['libAuth'] = $libAuth;
    }
}


$libMenuInternet = $libModuleHandler->getMenuInternet();
$libMenuIntranet = $libModuleHandler->getMenuIntranet();
$libMenuAdministration = $libModuleHandler->getMenuAdministration();


if (!isset($_GET['pid']) || $_GET['pid'] == '') {
    $defaultHomeExists = $libModuleHandler->pageExists($libConfig->defaultHome);

    if ($defaultHomeExists) {
        $libGlobal->pid = $libConfig->defaultHome;
    } else {
        $libGlobal->pid = 'login';
    }
} else {
    $libGlobal->pid = $_GET['pid'];
}

// If Keycloak is enabled and the user requested the login page, start the KC flow automatically
if (isset($libConfig->keycloakEnabled) && $libConfig->keycloakEnabled) {
    if (isset($libGlobal->pid) && $libGlobal->pid === 'login') {
        // Preserve optional pid target and start PKCE flow
        $startUrl = 'index.php?kc_start=1&pid=' . urlencode(isset($_GET['pid']) ? $_GET['pid'] : '');
        header('Location: ' . $startUrl, true, 302);
        exit;
    }
}


if (!$libModuleHandler->pageExists($libGlobal->pid)) {
    http_response_code(404);
    die('HTTP-Fehler 404: Seite nicht gefunden.');
} elseif (!$libSecurityManager->hasAccess($libModuleHandler->getPage($libGlobal->pid), $libAuth)) {
    http_response_code(403);
}


$libGlobal->page = $libModuleHandler->getPage($libGlobal->pid);
$libGlobal->module = $libModuleHandler->getModuleByPageid($libGlobal->pid);


require_once('vendor/vcms/layout/header.php');

if (is_object($libGlobal->page) && $libSecurityManager->hasAccess($libGlobal->page, $libAuth)) {
    if (is_file($libGlobal->page->getPath())) {
        require_once($libGlobal->page->getPath());
    }
} else {
    echo '<h1>Zugriffsfehler</h1>';
    echo $libString->getErrorBoxText();
    echo $libString->getNotificationBoxText();
    echo '<p class="mb-4">Für diese Seite ist eine <a href="index.php?pid=login">Anmeldung im Intranet</a> nötig.</p>';
}

require_once('vendor/vcms/layout/footer.php');
