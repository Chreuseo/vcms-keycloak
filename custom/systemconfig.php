<?php
class LibConfig{
	var $mysqlServer = 'localhost';
	var $mysqlUser = 'vcms';
	var $mysqlPass = 'Userpass1234567890';
	var $mysqlDb = 'vcms';
	var $mysqlPort = '3308';

	var $verbindungName = 'K.St.V. Example';
	var $verbindungDachverband = 'KV';

	var $verbindungZusatz = '';
	var $verbindungStrasse = 'Musterstr. 20';
	var $verbindungPlz = '12345';
	var $verbindungOrt = 'Musterstadt';
	var $verbindungLand = '';
	var $verbindungTelefon = '+49 251 123456789';

	var $seiteBeschreibung = 'Katholischer Studentenverein Example im Kartellverband katholischer deutscher Studentenvereine (KV) zu Münster (Westf.)';
	var $seiteKeywords = 'Studentenverbindung, Universität, Verbindung, Studentenverein, Student';
	var $emailInfo = 'kontakt@example.net';
	var $emailWebmaster = 'webmaster@example.net';

	var $chargenSenior = 'x';
	var $chargenJubelSenior = 'x';
	var $chargenConsenior = 'vx';
	var $chargenScriptor = 'xx';
	var $chargenQuaestor = 'xxx';
	var $chargenFuchsmajor = 'FM';
	var $chargenFuchsmajor2 = 'FM 2';
	var $chargenAHVSenior = 'AH-x';
	var $chargenAHVConsenior = 'AH-vx';
	var $chargenAHVKeilbeauftragter = 'K';
	var $chargenAHVScriptor = 'AH-xx';
	var $chargenAHVQuaestor = 'AH-xxx';
	var $chargenHVVorsitzender = '';
	var $chargenHVKassierer = '';
	var $chargenArchivar = '';
	var $chargenRedaktionswart = 'Red.';
	var $chargenVOP = 'VOP';
	var $chargenVVOP = 'VVOP';
	var $chargenVOPxx = 'VOPxx';
	var $chargenVOPxxx = 'VOPxxx';
	var $chargenVOPxxxx = 'VOPxxxx';

	/**
	* Zeitzone, normalerweise unverändert
	* Valide Werte unter http://www.php.net/manual/de/timezones.php
	*/
	var $timezone = 'Europe/Berlin';

	/**
	* optionale Anpassungen
	*/
	var $defaultHome = 'home';

	// --- Keycloak Konfiguration (NEU) ---------------------------------------
	// Aktiviert die JWT Keycloak Authentifizierung
	var $keycloakEnabled = true; // auf true setzen um zu aktivieren
	// Public Key (RSA) des Realms (ohne BEGIN/END nötig – wird ergänzt)
	var $keycloakPublicKey = 'MIIClzCCAX8CBgGZWJbtnTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDAR2Y21zMB4XDTI1MDkxNzE2NTAxMFoXDTM1MDkxNzE2NTE1MFowDzENMAsGA1UEAwwEdmNtczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMH06J/n7DRZC1RAMn7rFt4meZOfqoj5YMjWtMQZ6G84FM5arcBUsLz0iphzdL53uty8GIE++2ADmv4nk3kOtYBJRqui6a5gUwG7LGrxI9qA6kvHlvL9bKKJOHBcwb0lAzEwkjLGbMvqOlOeuWXCoD6sWCsqV6UmXdK2FFB7U3paREE/7cNiCg+Rbvbxs/mBfkysyUPWXUbkcmR4brpDa0KiseuEcH8KmWF/6zASP8akYavGaxe2p9eWxDim6eb5wTWuDIueqCL2JqMjIuXGSVywIApWvPgRCXGBjVvh63RCmGtSSH/u4H8mvwh5eboXs6tj8mTgGPI27hPKEUKrLfkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEApfMWURnJ/iLwJuekxcluYe7h39shD8AzIWoNGw+lpwB/tMJQb41/Xl/RZ5dO0RSAxxw+w/JrFTLRdePIcOZ9X0+Ls0UA0bN+AYJUgyRJZMNwDXeHPjZKgv2gd1bg3RvChkM8nbxOzaK2ODm0PIc/jhdIR8qOanuMEOQw/edeUOBgC9iAjAQFYfwPQt/B3+OWreqE5ffvO2pDYrxBqglxINhMFwr6rufbjzlrfvrCEawxcFMmC/O6rcRIKNGhjadZCZJJ1BNMEA+BBDoCznlb+3vbV5Z8JtmvnO8HRSaUaODy6TdE1gpPDGHcEZuJYB9xZA+mh2ya0zfOIKh/vxHHlw==';
	// Erlaubte Issuer (Realm URL), leeres Array => keine Prüfung
	var $keycloakAllowedIssuers = array('http://localhost:8700/realms/aktivenkasse2'); // z.B. array('https://sso.example.org/realms/Example')
	// Erlaubte Audiences (Client IDs), leeres Array => keine Prüfung
	var $keycloakAllowedAudiences = array('vcms'); // z.B. array('vcms-frontend')
	// Standardgruppe für neu angelegte Benutzer (muss existieren)
	var $keycloakDefaultGroup = 'Aktiv'; // z.B. 'Aktiv'
	// Optional: explizite Client-ID, falls sie nicht mit der Audience übereinstimmt
	var $keycloakClientId = 'vcms';
	// Optional: für vertrauliche Clients – leer lassen für Public Clients
	var $keycloakClientSecret = 'bbhoiYspz2nyZEYVXim4x3hu35pD8wvg';
	// Optional: Auth-Methode für vertrauliche Clients: 'post' (client_secret_post) oder 'basic' (client_secret_basic)
	var $keycloakClientAuthMethod = 'post';
	// -------------------------------------------------------------------------

	/*
	* Standardmäßig liegt das Wintersemester im System von Oktober bis März und das Sommersemester von April bis Oktober.
	* Normalerweise sind Anpassungen nicht nötig, sodass die weitere Beschreibung nur für folgenden Spezialfälle gilt:
	* NUR FALLS SEMESTER IN ANDEREN MONATEN LIEGEN SOLLEN ODER ANDERE SEMESTER ALS WS & SS GEWÜNSCHT SIND,
	* kann durch Entfernen der folgenden // konfiguriert werden, welche Semester in welchen Monaten liegen:
	*
	* Im Beispiel liegt seit dem Jahr 0 das Sommersemester (SS) von Monat 4 (April) bis Monat 9 (September) und
	* das Wintersemester (WS) von Monat 10 (Oktober) bis Monat 3 (März), sowie seit dem Jahr 2008 der first term (FT)
	* von Monat 1 (Januar) bis Monat 6 (Juni) und der second term (ST) von Monat 7 (Juli) bis Monat 12 (Dezember).
	*
	* Das Beispiel kann abgeändert werden: Weitere Jahre können hinzugefügt werden;
	* Semesterpräfixe (SS, WS, FT, ST, ...) können geändert werden, dürfen aber nur aus GENAU 2 Zeichen aus a-z und A-Z
	* bestehen. Jedes Jahr muss zudem GENAU 12 Monate bzw. 12 Semesterpräfixe enthalten! Das Jahr 0 muss vorhanden sein.
	*/
	//var $semestersConfig = array(
	//	0 		=> array('WS', 'WS', 'WS', 'SS', 'SS', 'SS', 'SS', 'SS', 'SS', 'WS', 'WS', 'WS'),
	//	2008 	=> array('FT', 'FT', 'FT', 'FT', 'FT', 'FT', 'ST', 'ST', 'ST', 'ST', 'ST', 'ST')
	//);
}
