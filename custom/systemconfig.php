<?php

class LibConfig
{
    public $mysqlServer = 'localhost';
    public $mysqlUser = 'username';
    public $mysqlPass = 'password';
    public $mysqlDb = 'datenbankname';
    public $mysqlPort = '';

    public $verbindungName = 'K.St.V. Example';
    public $verbindungDachverband = 'KV';

    public $verbindungZusatz = '';
    public $verbindungStrasse = 'Musterstr. 20';
    public $verbindungPlz = '12345';
    public $verbindungOrt = 'Musterstadt';
    public $verbindungLand = '';
    public $verbindungTelefon = '+49 251 123456789';

    public $seiteBeschreibung = 'Katholischer Studentenverein Example im Kartellverband katholischer deutscher Studentenvereine (KV) zu Münster (Westf.)';
    public $seiteKeywords = 'Studentenverbindung, Universität, Verbindung, Studentenverein, Student';
    public $emailInfo = 'kontakt@example.net';
    public $emailWebmaster = 'webmaster@example.net';

    public $chargenSenior = 'x';
    public $chargenJubelSenior = 'x';
    public $chargenConsenior = 'vx';
    public $chargenScriptor = 'xx';
    public $chargenQuaestor = 'xxx';
    public $chargenFuchsmajor = 'FM';
    public $chargenFuchsmajor2 = 'FM 2';
    public $chargenAHVSenior = 'AH-x';
    public $chargenAHVConsenior = 'AH-vx';
    public $chargenAHVKeilbeauftragter = 'K';
    public $chargenAHVScriptor = 'AH-xx';
    public $chargenAHVQuaestor = 'AH-xxx';
    public $chargenHVVorsitzender = '';
    public $chargenHVKassierer = '';
    public $chargenArchivar = '';
    public $chargenRedaktionswart = 'Red.';
    public $chargenVOP = 'VOP';
    public $chargenVVOP = 'VVOP';
    public $chargenVOPxx = 'VOPxx';
    public $chargenVOPxxx = 'VOPxxx';
    public $chargenVOPxxxx = 'VOPxxxx';

    /**
     * Timezone, normally unchanged
     * Valid values at http://www.php.net/manual/de/timezones.php
     */
    public $timezone = 'Europe/Berlin';

    /**
     * Optional adjustments
     */
    public $defaultHome = 'home';

    // --- Keycloak configuration (kept for this fork) ------------------------
    // Enable JWT Keycloak authentication
    public $keycloakEnabled = false; // set to true to enable
    // Public Key (RSA) of the realm (BEGIN/END will be added automatically if omitted)
    public $keycloakPublicKey = '';
    // Allowed issuers (realm URL), empty array => no check
    public $keycloakAllowedIssuers = array(''); // e.g. array('https://sso.example.org/realms/Example')
    // Allowed audiences (client IDs), empty array => no check
    public $keycloakAllowedAudiences = array(''); // e.g. array('vcms-frontend')
    // Default group for newly created users (must exist)
    public $keycloakDefaultGroup = 'Y';
    // Optional: explicit client id if it does not match the audience
    public $keycloakClientId = '';
    // Optional: for confidential clients – leave empty for public clients
    public $keycloakClientSecret = '';
    // Optional: auth method for confidential clients: 'post' (client_secret_post) or 'basic'
    public $keycloakClientAuthMethod = 'post';
    // -------------------------------------------------------------------------

    //var $semestersConfig = array(
    //    0       => array('WS', 'WS', 'WS', 'SS', 'SS', 'SS', 'SS', 'SS', 'SS', 'WS', 'WS', 'WS'),
    //    2008    => array('FT', 'FT', 'FT', 'FT', 'FT', 'FT', 'ST', 'ST', 'ST', 'ST', 'ST', 'ST')
    //);
}
