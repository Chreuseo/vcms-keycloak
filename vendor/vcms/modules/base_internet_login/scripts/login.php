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

if (!is_object($libGlobal)) {
    exit();
}


/*
* configuration
*/

if (!$libGenericStorage->attributeExistsInCurrentModule('ssl_proxy_url')) {
    $libGenericStorage->saveValueInCurrentModule('ssl_proxy_url', '');
}


echo '<h1>Intranet-Login</h1>';

echo $libString->getErrorBoxText();
echo $libString->getNotificationBoxText();

$urlPrefix = '';

if ($libGlobal->getSiteUrlAuthority() != '') {
    $sslProxyUrl = $libGenericStorage->loadValueInCurrentModule('ssl_proxy_url');

    if ($sslProxyUrl != '') {
        $urlPrefix = 'https://' . $sslProxyUrl . '/' . $libGlobal->getSiteUrlAuthority() . '/';
    }
}

if (isset($libConfig->keycloakEnabled) && $libConfig->keycloakEnabled) {
    // Show Keycloak SSO button
    $kcStartUrl = 'index.php?kc_start=1&pid=' . rawurlencode($libGlobal->pid ?? 'login');
    echo '<div class="card mb-3">';
    echo '<div class="card-body">';
    echo '<p>Single Sign-On ist aktiviert. Bitte mit deinem Identitätsanbieter anmelden.</p>';
    echo '<a class="btn btn-primary" href="' . $libString->protectXSS($kcStartUrl) . '"><i class="fa fa-sign-in" aria-hidden="true"></i> Anmeldung über SSO</a>';
    echo '</div>';
    echo '</div>';

    // Optionally do not show local login form when Keycloak is enabled to avoid confusion
    echo '<p class="text-muted">Falls Du Dich lokal anmelden möchtest, deaktiviere Keycloak in der Konfiguration.</p>';
} else {
    echo '<div class="card">';
    echo '<div class="card-body">';
    echo '<form action="' .$libString->protectXSS($urlPrefix). 'index.php?pid=intranet_home" method="post">';
    echo '<fieldset>';

    $libForm->printTextInput('intranet_login_email', 'E-Mail-Adresse', '', 'email', false, true);
    $libForm->printTextInput('intranet_login_password', 'Passwort', '', 'password', false, true);
    $libForm->printSubmitButton('<i class="fa fa-sign-in" aria-hidden="true"></i> Anmelden');

    echo '</fieldset>';
    echo '</form>';
    echo '</div>';
    echo '</div>';
}

echo '<h2>Registrierung</h2>';
echo '<p class="mb-4">Um in das Intranet zu gelangen, wird ein Zugang benötigt, der von Mitgliedern auf der <a href="index.php?pid=registration">Registrierungsseite</a> angefordert werden kann.</p>';

echo '<h2>Passwort vergessen?</h2>';
echo '<p class="mb-4">Falls Du bereits einen Intranetzugang hast, aber das Passwort vergessen hast, kannst Du Dir <a href="index.php?pid=password">ein neues Passwort</a> per Email zuschicken lassen.</p>';
