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

if(!is_object($libGlobal) || !$libAuth->isLoggedin())
	exit();


// synchronize tables
$libDb->query("INSERT INTO mod_rundbrief_empfaenger (id, empfaenger) SELECT id, 1 FROM base_person WHERE (SELECT COUNT(*) FROM mod_rundbrief_empfaenger WHERE id=base_person.id) = 0");

/*
* receiver counters
*/
$stmt = $libDb->prepare("SELECT COUNT(*) AS number FROM base_person, mod_rundbrief_empfaenger WHERE base_person.id = mod_rundbrief_empfaenger.id AND email != '' AND email IS NOT NULL AND empfaenger=1 AND gruppe='F'");
$stmt->execute();
$stmt->bindColumn('number', $anzahlFuechse);
$stmt->fetch();

$stmt = $libDb->prepare("SELECT COUNT(*) AS number FROM base_person, mod_rundbrief_empfaenger WHERE base_person.id = mod_rundbrief_empfaenger.id AND email != '' AND email IS NOT NULL AND empfaenger=1 AND gruppe='B'");
$stmt->execute();
$stmt->bindColumn('number', $anzahlBurschen);
$stmt->fetch();

$streetNormalized = $libString->normalizeStreet($libConfig->verbindungStrasse);

$stmt = $libDb->prepare("SELECT COUNT(*) AS number FROM base_person, mod_rundbrief_empfaenger WHERE base_person.id = mod_rundbrief_empfaenger.id AND email != '' AND email IS NOT NULL AND empfaenger=1 AND (gruppe='F' OR gruppe='B') AND plz1=:plz AND strasse1 LIKE :street");
$stmt->bindValue(':plz', $libConfig->verbindungPlz);
$stmt->bindValue(':street', '%' .$streetNormalized. '%');
$stmt->execute();
$stmt->bindColumn('number', $anzahlHausbewohner);
$stmt->fetch();

$stmt = $libDb->prepare("SELECT COUNT(*) AS number FROM base_person, mod_rundbrief_empfaenger WHERE base_person.id = mod_rundbrief_empfaenger.id AND email != '' AND email IS NOT NULL AND empfaenger=1 AND gruppe='P'");
$stmt->execute();
$stmt->bindColumn('number', $anzahlAhah);
$stmt->fetch();

$stmt = $libDb->prepare("SELECT COUNT(*) AS number FROM base_person, mod_rundbrief_empfaenger WHERE base_person.id = mod_rundbrief_empfaenger.id AND email != '' AND email IS NOT NULL AND empfaenger=1 AND gruppe='P' AND interessiert= 1");
$stmt->execute();
$stmt->bindColumn('number', $anzahlBesondersInteressierteAhah);
$stmt->fetch();

$stmt = $libDb->prepare("SELECT COUNT(*) AS number FROM base_person, mod_rundbrief_empfaenger WHERE base_person.id = mod_rundbrief_empfaenger.id AND email != '' AND email IS NOT NULL AND empfaenger=1 AND gruppe='C'");
$stmt->execute();
$stmt->bindColumn('number', $anzahlCouleurdamen);
$stmt->fetch();

$stmt = $libDb->prepare("SELECT COUNT(*) AS number FROM base_person, mod_rundbrief_empfaenger WHERE base_person.id = mod_rundbrief_empfaenger.id AND email != '' AND email IS NOT NULL AND empfaenger=1 AND (gruppe='G' OR gruppe='W')");
$stmt->execute();
$stmt->bindColumn('number', $anzahlGattinnen);
$stmt->fetch();

$stmt = $libDb->prepare("SELECT COUNT(*) AS number FROM base_person, mod_rundbrief_empfaenger WHERE base_person.id = mod_rundbrief_empfaenger.id AND email != '' AND email IS NOT NULL AND empfaenger=1 AND (gruppe='G' OR gruppe='W') AND interessiert=1");
$stmt->execute();
$stmt->bindColumn('number', $anzahlBesondersInteressierteGattinnen);
$stmt->fetch();


/*
* configuration
*/

if(!$libGenericStorage->attributeExistsInCurrentModule('preselect_int_ahah')){
	$libGenericStorage->saveValueInCurrentModule('preselect_int_ahah', 1);
}


echo '<h1>Rundbrief an Mitglieder verschicken</h1>';

echo $libString->getErrorBoxText();
echo $libString->getNotificationBoxText();


echo '<div class="panel panel-default">';
echo '<div class="panel-body">';
echo '<form action="index.php?pid=intranet_rundbrief_senden" method="post" enctype="multipart/form-data" onsubmit="return confirm(\'Willst Du die Nachricht wirklich verschicken?\');" class="form-horizontal">';
echo '<fieldset>';

echo '<div class="form-group">';
echo '<label class="col-sm-3 control-label">Adressaten</label>';
echo '<div class="col-sm-4">';

echo '<div class="checkbox"><label><input type="checkbox" name="fuchsia" checked="checked">';
echo $anzahlFuechse. ' Füchse &amp; Fuchsmajor';
echo '</label></div>';

echo '<div class="checkbox"><label><input type="checkbox" name="burschen" checked="checked">';
echo $anzahlBurschen. ' Burschen';
echo '</label></div>';

$ahahInteressiertChecked = '';

if($libGenericStorage->loadValueInCurrentModule('preselect_int_ahah') == 1){
	$ahahInteressiertChecked = 'checked="checked"';
}

echo '<div class="checkbox"><label><input type="checkbox" name="ahah_interessiert" ' .$ahahInteressiertChecked. '>';
echo $anzahlBesondersInteressierteAhah. ' besonders interessierte alte Herren';
echo '</label></div>';

echo '<div class="checkbox"><label><input type="checkbox" name="ahah">';
echo $anzahlAhah. ' alte Herren';
echo '</label></div>';

echo '</div>';
echo '<div class="col-sm-4">';

echo '<div class="checkbox"><label><input type="checkbox" name="hausbewohner">';
echo $anzahlHausbewohner. ' Hausbewohner';
echo '</label></div>';

echo '<div class="checkbox"><label><input type="checkbox" name="couleurdamen">';
echo $anzahlCouleurdamen. ' Couleurdamen';
echo '</label></div>';

echo '<div class="checkbox"><label><input type="checkbox" name="gattinnen_interessiert">';
echo $anzahlBesondersInteressierteGattinnen. ' besonders interessierte Gattinnen';
echo '</label></div>';

echo '<div class="checkbox"><label><input type="checkbox" name="gattinnen">';
echo $anzahlGattinnen. ' Gattinnen';
echo '</label></div>';

echo '</div></div>';

$libForm->printRegionDropDownBox("region", "Nach Region", "");

echo '<hr />';

$formattedMitgliedNameString = $libPerson->formatNameString($libAuth->getAnrede(), $libAuth->getTitel(), '', $libAuth->getVorname(), $libAuth->getPraefix(), $libAuth->getNachname(), $libAuth->getSuffix(), 4);

$stmt = $libDb->prepare("SELECT email FROM base_person WHERE id=:id");
$stmt->bindValue(':id', $libAuth->getId(), PDO::PARAM_INT);
$stmt->execute();
$stmt->bindColumn('email', $email);
$stmt->fetch();

$formattedSenderString = $formattedMitgliedNameString. ' &lt;' .$email. '&gt;';

$libForm->printStaticText('Absender', $formattedSenderString);
$libForm->printTextInput('subject', 'Betreff', '');
echo '<div class="form-group">';
echo '<label class="col-sm-3 control-label">Anhang</label>';
echo '<div class="col-sm-9">';
echo '<label class="btn btn-default btn-file"><i class="fa fa-paperclip" aria-hidden="true"></i> Datei hinzufügen';
echo '<input type="file" id="anhang-picker" multiple style="display:none">';
echo '</label>';
echo '<input type="file" id="anhang-input" name="anhang[]" multiple style="display:none">';
echo '<ul id="anhang-liste" style="list-style:none; padding-left:0; margin-top:8px;"></ul>';
echo '</div>';
echo '</div>';
echo '<script>';
echo '(function(){';
echo '  var dt = new DataTransfer();';
echo '  document.getElementById("anhang-picker").addEventListener("change", function(){';
echo '    for(var i = 0; i < this.files.length; i++){ dt.items.add(this.files[i]); }';
echo '    this.value = "";';
echo '    updateAnhangListe();';
echo '  });';
echo '  window.removeAnhang = function(i){';
echo '    dt.items.remove(i);';
echo '    updateAnhangListe();';
echo '  };';
echo '  function updateAnhangListe(){';
echo '    var ul = document.getElementById("anhang-liste");';
echo '    ul.innerHTML = "";';
echo '    for(var i = 0; i < dt.files.length; i++){';
echo '      (function(idx){';
echo '        var li = document.createElement("li");';
echo '        li.style.marginBottom = "4px";';
echo '        var name = dt.files[idx].name;';
echo '        var size = (dt.files[idx].size / 1024).toFixed(1) + " KB";';
echo '        li.innerHTML = \'<i class="fa fa-file-o" aria-hidden="true"></i> \' + name + \' <small class="text-muted">(\' + size + \')</small> \'';
echo '          + \'<a href="#" onclick="removeAnhang(\' + idx + \'); return false;" class="text-danger" title="Entfernen"><i class="fa fa-times" aria-hidden="true"></i></a>\';';
echo '        ul.appendChild(li);';
echo '      })(i);';
echo '    }';
echo '    document.getElementById("anhang-input").files = dt.files;';
echo '  }';
echo '})();';
echo '</script>';
$libForm->printTextarea('nachricht', 'Nachricht', '');
$libForm->printSubmitButton('<i class="fa fa-envelope-o" aria-hidden="true"></i> Nachricht verschicken');

echo '</fieldset>';
echo '</form>';
echo '</div>';
echo '</div>';
