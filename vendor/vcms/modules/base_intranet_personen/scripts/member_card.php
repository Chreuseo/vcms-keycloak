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

// Zugriffsschutz: nur eingeloggte Nutzer
if(!isset($libAuth) || !is_object($libAuth) || !method_exists($libAuth, 'isLoggedin') || !$libAuth->isLoggedin())
	exit();

// Erwarte zentrale VCMS-Objekte; bei fehlendem Kontext abbrechen (und Hilfszuweisungen für Linter)
if(!isset($libDb) || !is_object($libDb)) { exit(); }
if(!isset($libPerson) || !is_object($libPerson)) { exit(); }
if(!isset($libConfig) || !is_object($libConfig)) { $libConfig = (object)[]; }
if(!isset($libString)) { $libString = null; }

// Optional: Auto-Geocoding deaktivieren per URL-Parameter ?geocode=0
$autoGeocode = true;
if(isset($_GET['geocode'])){
	$gv = strtolower(trim((string)$_GET['geocode']));
	if($gv === '0' || $gv === 'false' || $gv === 'no'){
		$autoGeocode = false;
	}
}

// Sammle Basisdaten der Personen inkl. Adressen
$stmt = $libDb->prepare("SELECT id, anrede, titel, rang, vorname, praefix, name, suffix, gruppe,
    zusatz1, strasse1, ort1, plz1, land1,
    zusatz2, strasse2, ort2, plz2, land2
    FROM base_person
    WHERE gruppe != 'X' AND gruppe != 'T' AND gruppe != 'C'
");
$stmt->execute();

$members = [];
while($row = $stmt->fetch(PDO::FETCH_ASSOC)){
    $id = (int)$row['id'];

    // Anzeigename über Helper
    $displayName = $libPerson->getNameString($id, 0);

    // Bevorzugte Adresse wählen (1 vor 2)
    $addrParts1 = [];
    if(!empty($row['zusatz1'])) $addrParts1[] = $row['zusatz1'];
    if(!empty($row['strasse1'])) $addrParts1[] = $row['strasse1'];
    $plz1 = isset($row['plz1']) ? $row['plz1'] : '';
    $ort1 = isset($row['ort1']) ? $row['ort1'] : '';
    $cityLine1 = trim($plz1.' '.$ort1);
    if(!empty($cityLine1)) $addrParts1[] = $cityLine1;
    if(!empty($row['land1'])) $addrParts1[] = $row['land1'];
    $address1 = trim(implode(', ', array_filter($addrParts1)));

    $addrParts2 = [];
    if(!empty($row['zusatz2'])) $addrParts2[] = $row['zusatz2'];
    if(!empty($row['strasse2'])) $addrParts2[] = $row['strasse2'];
    $plz2 = isset($row['plz2']) ? $row['plz2'] : '';
    $ort2 = isset($row['ort2']) ? $row['ort2'] : '';
    $cityLine2 = trim($plz2.' '.$ort2);
    if(!empty($cityLine2)) $addrParts2[] = $cityLine2;
    if(!empty($row['land2'])) $addrParts2[] = $row['land2'];
    $address2 = trim(implode(', ', array_filter($addrParts2)));

    $chosenAddress = $address1 !== '' ? $address1 : $address2;

    if($chosenAddress === ''){
        // Ohne Adresse nicht auf Karte anzeigen
        continue;
    }

    $members[] = [
        'id' => $id,
        'name' => $displayName,
        'group' => $row['gruppe'],
        'address' => $chosenAddress
    ];
}

// Seite ausgeben
$titlePrefix = (isset($libConfig) && isset($libConfig->verbindungName)) ? $libConfig->verbindungName : 'VCMS';
echo '<h1>' .$titlePrefix. ' - Mitgliederkarte</h1>';

echo isset($libString) ? $libString->getErrorBoxText() : '';
echo isset($libString) ? $libString->getNotificationBoxText() : '';

// Hinweistext
echo '<div class="alert alert-info">';
echo 'Diese Karte nutzt OpenStreetMap-Karten. Adressen werden (sofern nicht im Cache) clientseitig per Nominatim geokodiert und lokal im Browser zwischengespeichert.';
echo '</div>';

// Kartencontainer
echo '<div id="member-map" style="height: 70vh; width: 100%; border: 1px solid #ddd; border-radius: 4px;"></div>';

// Steuerleiste
if(!$autoGeocode){
	echo '<p class="mt-2"><a class="btn btn-primary" href="index.php?pid=intranet_mitglied_karte">Geocoding starten</a> ';
	echo '<a class="btn btn-default" href="index.php?pid=intranet_mitglied_karte&amp;geocode=0">Geocoding auslassen</a></p>';
}

// Daten als JSON einbetten
$membersJson = json_encode($members, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP);
$autoGeocodeJs = $autoGeocode ? 'true' : 'false';

// Leaflet & MarkerCluster via CDN einbinden und Karte initialisieren
?>
<link
  rel="stylesheet"
  href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
  integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="
  crossorigin=""/>
<link
  rel="stylesheet"
  href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css"
/>
<link
  rel="stylesheet"
  href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css"
/>
<script
  src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
  integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
  crossorigin="">
</script>
<script src="https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js"></script>
<script>
(function(){
  var MEMBERS = <?php echo $membersJson ?: '[]'; ?>;
  var AUTO_GEOCODE = <?php echo $autoGeocodeJs; ?>;

  // Basiskarte
  var map = L.map('member-map', {
    scrollWheelZoom: true
  }).setView([51.1657, 10.4515], 5); // Deutschland als Start

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19,
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> Mitwirkende'
  }).addTo(map);

  var cluster = L.markerClusterGroup({
    showCoverageOnHover: false,
    spiderfyOnMaxZoom: true,
    maxClusterRadius: 60
  });

  var addrToMembers = new Map();
  MEMBERS.forEach(function(m){
    var key = (m.address || '').trim();
    if(!key) return;
    if(!addrToMembers.has(key)) addrToMembers.set(key, []);
    addrToMembers.get(key).push(m);
  });

  // Einfacher LocalStorage-Cache
  var CACHE_KEY = 'vcms_geocode_cache_v1';
  var cache = (function(){
    try {
      var raw = localStorage.getItem(CACHE_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch(e) { return {}; }
  })();
  function saveCache(){
    try { localStorage.setItem(CACHE_KEY, JSON.stringify(cache)); } catch(e) {}
  }

  var pending = [];
  addrToMembers.forEach(function(_v, address){
    if(cache[address]){
      addMarkersFor(address, cache[address]);
    } else {
      pending.push(address);
    }
  });

  // Marker hinzufügen (ggf. mehrere Mitglieder pro Adresse zusammenfassen)
  function addMarkersFor(address, coords){
    var list = addrToMembers.get(address) || [];
    if(list.length === 0) return;

    // Popup-HTML: mehrere Einträge untereinander
    var html = list.map(function(m){
      var url = 'index.php?pid=intranet_person&id=' + encodeURIComponent(m.id);
      return '<div class="mb-2">'
        + '<a href="' + url + '"><strong>' + escapeHtml(m.name) + '</strong></a>'
        + '<br/><small>' + escapeHtml(address) + '</small>'
        + '</div>';
    }).join('');

    var marker = L.marker([coords.lat, coords.lon]);
    marker.bindPopup(html, { maxWidth: 320 });
    cluster.addLayer(marker);
  }

  function escapeHtml(str){
    return String(str)
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/\"/g,'&quot;')
      .replace(/'/g,'&#039;');
  }

  // Geocoding-Queue mit sanfter Rate (1 Request / Sekunde)
  var idx = 0;
  function tick(){
    if(idx >= pending.length){
      // Nach letztem Geocode Karte an Daten anpassen
      fitIfPossible();
      return;
    }
    var address = pending[idx++];
    geocode(address).then(function(coords){
      if(coords){
        cache[address] = coords; // Cache aktualisieren
        saveCache();
        addMarkersFor(address, coords);
      }
    }).catch(function(){ }).finally(function(){
      setTimeout(tick, 1000);
    });
  }

  // Nominatim-Geocoding (Browser, mit höflichen Headern)
  function geocode(address){
    var url = 'https://nominatim.openstreetmap.org/search?format=json&limit=1&q=' + encodeURIComponent(address);
    return fetch(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'VCMS-Intranet-Map/1.0 (contact: admin@example.com)'
      }
    }).then(function(resp){
      if(!resp.ok) return null;
      return resp.json();
    }).then(function(data){
      if(data && data[0]){
        return { lat: parseFloat(data[0].lat), lon: parseFloat(data[0].lon) };
      }
      return null;
    }).catch(function(){ return null; });
  }

  // Vorhandene Marker in die Karte und Bounds setzen
  map.addLayer(cluster);

  function fitIfPossible(){
    var bounds = cluster.getBounds();
    if(bounds && bounds.isValid()){
      map.fitBounds(bounds.pad(0.1));
    }
  }

  // Zuerst alle gecachten Adressen anzeigen
  setTimeout(fitIfPossible, 100);
  // Geocoding nur, wenn erlaubt
  if(AUTO_GEOCODE && pending.length > 0){ tick(); }
})();
</script>
