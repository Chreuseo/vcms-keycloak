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

if(!isset($libGlobal) || !is_object($libGlobal)) {
	exit();
}

// Static page "Meine Dienste"

echo '<h1>Meine Dienste</h1>';

echo '<p class="mb-4">Schnellzugriff auf häufig genutzte Dienste.</p>';

// Inline-Styles für gleich hohe Kacheln per Flexbox
// Hinweis: Wir nutzen eine eigene Klasse services-grid, um Bootstrap-Defaults nicht global zu überschreiben.
echo '<style>
.services-grid { display: flex; flex-wrap: wrap; align-items: stretch; margin-left: -15px; margin-right: -15px; }
.services-grid > [class*="col-"] { display: flex; padding-left: 15px; padding-right: 15px; flex: 0 0 33.3333%; max-width: 33.3333%; min-width: 0; }
.service-card { display: block; width: 100%; height: 100%; }
.service-card .panel { display: flex; flex-direction: column; width: 100%; height: 100%; }
.service-card .panel-body { display: flex; flex-direction: column; align-items: center; text-align: center; flex: 1; }
.service-title { margin-top: 6px; overflow-wrap: anywhere; word-break: break-word; hyphens: auto; }
.service-desc { margin-top: 4px; overflow-wrap: anywhere; word-break: break-word; hyphens: auto; }
@media (max-width: 991px) { .services-grid > [class*="col-"] { flex: 0 0 50%; max-width: 50%; } }
@media (max-width: 767px) { .services-grid > [class*="col-"] { flex: 0 0 100%; max-width: 100%; } }
</style>';

// Basis-URL für modul-lokale Assets (Web) und Pfad (Dateisystem)
$assetBaseUrl  = (isset($libModuleHandler) && is_object($libModuleHandler)) ? ($libModuleHandler->getModuleDirectory().'/custom') : 'modules/mod_internet_dienste/custom';
$assetFileBase = dirname(__DIR__) . '/custom';

$services = [
	[
		'title' => 'Webseite',
		'desc'  => 'Startseite dieser Website',
		'url'   => 'index.php',
		// Beispiel: Bild statt Icon verwenden (Datei in custom/ ablegen)
		'image' => 'home.png',
		'icon'  => 'fa-home', // Fallback, falls kein Bild vorhanden/gewünscht
		'external' => false,
	],
	[
		'title' => 'Keycloak Self-Service',
		'desc'  => 'Account-Verwaltung',
		'url'   => 'https://keycloak.kstv-burggraf.de/realms/burggraf/account/',
        'image' => 'keycloak.png',
		'icon'  => 'fa-user',
		'external' => true,
	],
	[
		'title' => 'Keycloak Admin-Oberfläche',
		'desc'  => 'Nutzerverwaltung',
		'url'   => 'https://keycloak.kstv-burggraf.de/admin/burggraf/console/',
        'image' => 'keycloak.png',
		'icon'  => 'fa-key',
		'external' => true,
	],
    [
        'title' => 'Mitgliederverwaltung',
        'desc' => 'Mitgliederverwaltung',
        'url' => 'https://mitgliederverwaltung.kstv-burggraf.de',
        'image' => 'mitgliederverwaltung.png',
        'icon' => 'fa-users',
        'external' => true,
    ],
	[
		'title' => 'Burggraf-Cloud',
		'desc'  => 'Nextcloud',
		'url'   => 'https://cloud.kstv-burggraf.de',
        'image' => 'cloud.png',
		'icon'  => 'fa-cloud',
		'external' => true,
	],
	[
		'title' => 'Aktivenkasse',
		'desc'  => 'Kasse der Aktiven',
		'url'   => 'https://aktivenkasse.kstv-burggraf.de',
        'image' => 'aktivenkasse.png',
		'icon'  => 'fa-eur',
		'external' => true,
	],
    [
        'title' => 'Kartellverband (extern)',
        'desc' => 'Kartellverband katholischer deutscher Studentenvereine',
        'url' => 'https://www.kartellverband.de/login.html',
        'image' => 'kartellverband.png',
        'icon' => 'fa-external-link',
        'external' => true,
    ],
];

// Grid of service cards
// Uses Bootstrap panels and Font Awesome icons available in the theme

echo '<div class="row services-grid">';
foreach ($services as $svc) {
	$title = isset($libString) ? $libString->protectXSS($svc['title']) : htmlspecialchars($svc['title']);
	$desc  = isset($libString) ? $libString->protectXSS($svc['desc'])  : htmlspecialchars($svc['desc']);

	// Bild-Auflösung: nur verwenden, wenn Datei existiert
	$imgFilename = !empty($svc['image']) ? $svc['image'] : null;
	$imgFsPath   = $imgFilename ? ($assetFileBase . '/' . $imgFilename) : null;
	$hasImage    = $imgFsPath && file_exists($imgFsPath);
	$imgWebUrl   = $hasImage ? ($assetBaseUrl . '/' . $imgFilename) : null;

	$url = $svc['url'];
	if (!empty($svc['linkToImage']) && $hasImage) {
		$url = $imgWebUrl;
	}

	$ext   = !empty($svc['external']);
	$target = $ext ? ' target="_blank" rel="noopener noreferrer"' : '';

	echo '<div class="col-xs-12 col-sm-6 col-md-4 mb-4">';
	echo '<a class="service-card hvr-grow" href="' . $url . '"' . $target . '>';
	echo '  <div class="panel panel-default">';
	echo '    <div class="panel-body text-center">';

	// Symbol: bevorzugt Bild (wenn vorhanden), sonst Icon
	if ($hasImage) {
		echo '      <div class="service-icon mb-3">';
		echo '        <img src="' . $imgWebUrl . '" alt="' . $title . '" class="img-responsive center-block" style="width:150px;height:150px;object-fit:contain;" />';
		echo '      </div>';
	} else {
		$icon = !empty($svc['icon']) ? $svc['icon'] : 'fa-external-link';
		echo '      <div class="service-icon mb-3" style="font-size: 2.2em;">';
		echo '        <i class="fa ' . $icon . '" aria-hidden="true"></i>';
		echo '      </div>';
	}

	echo '      <div class="service-title" style="font-weight: 600;">' . $title . '</div>';
	echo '      <div class="service-desc text-muted">' . $desc . '</div>';
	echo '    </div>';
	echo '  </div>';
	echo '</a>';
	echo '</div>';
}
echo '</div>';

// Optional: small hint for external links
// echo '<p class="text-muted"><small>Externe Links öffnen in einem neuen Tab.</small></p>';
