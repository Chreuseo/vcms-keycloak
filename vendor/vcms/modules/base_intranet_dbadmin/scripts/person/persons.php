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

// Globale VCMS-Objekte aus $GLOBALS absichern (Shim für Linter)
$libGlobal = isset($libGlobal) ? $libGlobal : (isset($GLOBALS['libGlobal']) ? $GLOBALS['libGlobal'] : null);
$libAuth = isset($libAuth) ? $libAuth : (isset($GLOBALS['libAuth']) ? $GLOBALS['libAuth'] : null);
$libDb = isset($libDb) ? $libDb : (isset($GLOBALS['libDb']) ? $GLOBALS['libDb'] : null);
$libConfig = isset($libConfig) ? $libConfig : (isset($GLOBALS['libConfig']) ? $GLOBALS['libConfig'] : null);
$libString = isset($libString) ? $libString : (isset($GLOBALS['libString']) ? $GLOBALS['libString'] : null);
$libForm = isset($libForm) ? $libForm : (isset($GLOBALS['libForm']) ? $GLOBALS['libForm'] : null);
$libSecurityManager = isset($libSecurityManager) ? $libSecurityManager : (isset($GLOBALS['libSecurityManager']) ? $GLOBALS['libSecurityManager'] : null);
$libImage = isset($libImage) ? $libImage : (isset($GLOBALS['libImage']) ? $GLOBALS['libImage'] : null);

if(!is_object($libGlobal) || !$libAuth->isLoggedin())
	exit();


if($libAuth->isLoggedin()){
	$orderby = 0;

	if(isset($_POST['orderby'])){
		$orderby = $_POST['orderby'];
	}

	if(isset($_GET['aktion']) && $_GET['aktion'] == 'delete'){
		if(isset($_GET['id']) && $_GET['id'] != ''){
			//Ist der Bearbeiter kein Internetwart?
			if(!in_array('internetwart', $libAuth->getAemter()) && !in_array('datenpflegewart', $libAuth->getAemter())){
				die('Diese Aktion darf nur von einem Internetwart ausgeführt werden.');
			}

			//Problemfall Internetwart: Dieser darf nie gelöscht werden, um immer einen Admin im System zu haben
			$anzahl = 0; // init
			$stmt = $libDb->prepare('SELECT COUNT(*) AS number FROM base_semester WHERE internetwart=:internetwart');
			$stmt->bindValue(':internetwart', $_REQUEST['id'], PDO::PARAM_INT);
			$stmt->execute();
			$stmt->bindColumn('number', $anzahl);
			$stmt->fetch();

			if($anzahl > 0){
				$libGlobal->errorTexts[] = 'Die Person kann nicht gelöscht werden, weil sie ein Internetwart in mindestens einem Semester ist. Internetwarte können nicht gelöscht werden, weil sie die Administratoren sind und im Extremfall somit kein Administrator im System existiert. Falls diese Person gelöscht werden soll, so muss sie erst manuell von einem Internetwart in allen Semestern aus den Internetwartsposten entfernt werden.';
			} else {
				//Verwendung der Person in anderen Tabellen prüfen
				//diese Einträge vorher löschen oder vom Mitglied befreien

				//Veranstaltungsteilnahmen löschen
				$stmt = $libDb->prepare('DELETE FROM base_veranstaltung_teilnahme WHERE person=:id');
				$stmt->bindValue(':id', $_REQUEST['id'], PDO::PARAM_INT);
				$stmt->execute();

				//Vereinsmitgliedschaften löschen
				$stmt = $libDb->prepare('DELETE FROM base_verein_mitgliedschaft WHERE mitglied=:id');
				$stmt->bindValue(':id', $_REQUEST['id'], PDO::PARAM_INT);
				$stmt->execute();

				//Semesterämter löschen
				foreach($libSecurityManager->getPossibleAemter() as $amt){
					$stmt = $libDb->prepare('UPDATE base_semester SET '.$amt.' = NULL WHERE '.$amt.'=:id');
					$stmt->bindValue(':id', $_REQUEST['id'], PDO::PARAM_INT);
					$stmt->execute();
				}

				//Leibvaterangaben entfernen
				$stmt = $libDb->prepare('UPDATE base_person SET leibmitglied = NULL WHERE leibmitglied=:id');
				$stmt->bindValue(':id', $_REQUEST['id'], PDO::PARAM_INT);
				$stmt->execute();

				//Ehepartnerangaben entfernen
				$stmt = $libDb->prepare('UPDATE base_person SET heirat_partner = NULL WHERE heirat_partner=:id');
				$stmt->bindValue(':id', $_REQUEST['id'], PDO::PARAM_INT);
				$stmt->execute();

				//Mitglied aus Datenbank löschen
				$stmt = $libDb->prepare('DELETE FROM base_person WHERE id=:id');
				$stmt->bindValue(':id', $_REQUEST['id'], PDO::PARAM_INT);
				$stmt->execute();

				$libGlobal->notificationTexts[] = 'Datensatz gelöscht';

				//Fotodatei löschen
				$libImage->deletePersonFoto($_REQUEST['id']);
			}
		}
	}

	switch($orderby){
		case 0:
			$order = 'SUBSTRING(semester_reception, 3) DESC';
			break;
		case 1:
			$order = 'name, vorname, datum_geburtstag ASC';
			break;
		case 2:
			$order = 'gruppe, name, vorname ASC';
			break;
		case 3:
			$order = 'id ASC';
			break;
		default:
			$order = 'SUBSTRING(semester_reception, 3) DESC';
	}

	echo '<h1>Personen</h1>';

	$anzahl = 0; // init
	echo $libString->getErrorBoxText();
	echo $libString->getNotificationBoxText();

	// --- Keycloak Sync Panel + Aktionen ---
	$canAdminPerson = in_array('internetwart', $libAuth->getAemter()) || in_array('datenpflegewart', $libAuth->getAemter());
	if(isset($libConfig->keycloakEnabled) && $libConfig->keycloakEnabled){
		$kcAdminOk = method_exists($libAuth,'keycloakAdminAvailable') ? $libAuth->keycloakAdminAvailable() : false;

		// Aktionen nur wenn berechtigt und Adminzugriff
		if($canAdminPerson && $kcAdminOk && isset($_POST['kc_action'])){
			$libAuth->ensureKeycloakColumn();
			$action = $_POST['kc_action'];
			if($action === 'scan'){
				$autoCreate = isset($_POST['kc_create_missing']) && $_POST['kc_create_missing'] == '1';
				$updated=0; $linked=0; $createdRemote=0;
				// Lokale Personen laden (gültige Gruppen)
				$stmtAll = $libDb->prepare("SELECT id, vorname, name, email, keycloak_id FROM base_person WHERE (gruppe != 'T' AND gruppe != 'X' AND gruppe != 'V') OR gruppe IS NULL");
				$stmtAll->execute();
				$locals = $stmtAll->fetchAll(PDO::FETCH_ASSOC);
				$localEmails = array(); $localByKc = array();
				foreach($locals as $loc){ if(isset($loc['email']) && $loc['email']!=='') $localEmails[strtolower($loc['email'])]=$loc; if(isset($loc['keycloak_id']) && $loc['keycloak_id']!=='') $localByKc[$loc['keycloak_id']]=$loc; }
				// a) Update via keycloak_id
				foreach($locals as $loc){
					$kid = isset($loc['keycloak_id']) ? trim($loc['keycloak_id']) : '';
					if($kid !== ''){
						$remote = $libAuth->keycloakAdminGetUserById($kid);
						if(is_array($remote)){
							$first = isset($remote['firstName'])?trim($remote['firstName']):'';
							$last  = isset($remote['lastName'])?trim($remote['lastName']):'';
							$email = isset($remote['email'])?strtolower(trim($remote['email'])):'';
							$need=false;
							if($first!=='' && $first!=$loc['vorname']) $need=true;
							if($last!=='' && $last!=$loc['name']) $need=true;
							if($email!=='' && $email!=strtolower(trim($loc['email']))) $need=true;
							if($need){ $u=$libDb->prepare('UPDATE base_person SET vorname=:v, name=:n, email=:e WHERE id=:id'); $u->bindValue(':v',$first!==''?$first:$loc['vorname']); $u->bindValue(':n',$last!==''?$last:$loc['name']); $u->bindValue(':e',$email!==''?$email:$loc['email']); $u->bindValue(':id',$loc['id'],PDO::PARAM_INT); $u->execute(); $updated++; }
						}
					}
				}
				// b) Verknüpfen via E-Mail, optional in KC anlegen
				foreach($locals as $loc){
					if(!isset($loc['keycloak_id']) || trim($loc['keycloak_id'])===''){
						$email = isset($loc['email'])?strtolower(trim($loc['email'])):'';
						$remote = $email!=='' ? $libAuth->keycloakAdminGetUserByEmail($email) : null;
						if($remote && isset($remote['id'])){
							$u = $libDb->prepare('UPDATE base_person SET keycloak_id=:kid WHERE id=:id'); $u->bindValue(':kid',$remote['id']); $u->bindValue(':id',$loc['id'],PDO::PARAM_INT); $u->execute(); $linked++;
						}else if($autoCreate && $email!==''){
							$first = isset($loc['vorname'])?trim($loc['vorname']):''; $last = isset($loc['name'])?trim($loc['name']):'';
							$newId = $libAuth->keycloakAdminCreateUser($email,$first,$last);
							if($newId){ $u = $libDb->prepare('UPDATE base_person SET keycloak_id=:kid WHERE id=:id'); $u->bindValue(':kid',$newId); $u->bindValue(':id',$loc['id'],PDO::PARAM_INT); $u->execute(); $createdRemote++; }
						}
					}
				}
				$libGlobal->notificationTexts[] = 'Keycloak-Sync: ' . $updated . ' aktualisiert, ' . $linked . ' verknüpft, ' . $createdRemote . ' in Keycloak angelegt.';

				// c) Neue KC-Nutzer finden
				$kc_remote_new_list_admin = array(); $seenEmails = array_change_key_case($localEmails, CASE_LOWER); $seenByKid = $localByKc;
				$first=0; $max=200; $round=0; $limitRounds=10;
				while($round < $limitRounds){
					$list = $libAuth->keycloakAdminListUsers($max,$first);
					if(!is_array($list) || count($list)===0) break;
					foreach($list as $u){ $kid = isset($u['id'])?$u['id']:''; $em = isset($u['email'])?strtolower(trim($u['email'])):''; if($kid==='') continue; if(isset($seenByKid[$kid])) continue; if($em!=='' && isset($seenEmails[$em])) continue; $kc_remote_new_list_admin[] = array('id'=>$kid,'firstName'=>isset($u['firstName'])?trim($u['firstName']):'','lastName'=>isset($u['lastName'])?trim($u['lastName']):'','email'=>$em); }
					$first += $max; $round++;
				}
				$GLOBALS['kc_remote_new_list_admin'] = $kc_remote_new_list_admin;
			}
			elseif($action === 'import'){
				$ids = isset($_POST['kc_import_ids']) && is_array($_POST['kc_import_ids']) ? $_POST['kc_import_ids'] : array();
				$imported=0; $skipped=0;
				$defaultGroup = isset($libConfig->keycloakDefaultGroup)?$libConfig->keycloakDefaultGroup:'';
				if($defaultGroup===''){ $stmtG=$libDb->prepare('SELECT bezeichnung FROM base_gruppe WHERE bezeichnung NOT IN ("T","X","V") ORDER BY bezeichnung LIMIT 1'); $stmtG->execute(); $rowG=$stmtG->fetch(PDO::FETCH_ASSOC); $defaultGroup = $rowG ? $rowG['bezeichnung'] : 'Y'; }
				foreach($ids as $kid){ $kid=trim($kid); if($kid==='') continue; $chk=$libDb->prepare('SELECT id FROM base_person WHERE keycloak_id=:kid'); $chk->bindValue(':kid',$kid); $chk->execute(); if($chk->fetch(PDO::FETCH_ASSOC)){ $skipped++; continue; } $u=$libAuth->keycloakAdminGetUserById($kid); if(!$u){ $skipped++; continue; } $em = isset($u['email'])?strtolower(trim($u['email'])):''; $first = isset($u['firstName'])?trim($u['firstName']):''; $last = isset($u['lastName'])?trim($u['lastName']):(isset($u['username'])?trim($u['username']):''); if($em!==''){ $e=$libDb->prepare('SELECT id FROM base_person WHERE email=:email'); $e->bindValue(':email',$em); $e->execute(); $er=$e->fetch(PDO::FETCH_ASSOC); if($er){ $u2=$libDb->prepare('UPDATE base_person SET keycloak_id=:kid WHERE id=:id'); $u2->bindValue(':kid',$kid); $u2->bindValue(':id',$er['id'],PDO::PARAM_INT); $u2->execute(); $imported++; continue; } } $ins=$libDb->prepare('INSERT INTO base_person (anrede,titel,praefix,vorname,suffix,gruppe,name,email,password_hash,keycloak_id) VALUES ("","","",:vorname,"",:gruppe,:name,:email,"",:kid)'); $ins->bindValue(':vorname',$first); $ins->bindValue(':gruppe',$defaultGroup); $ins->bindValue(':name',$last!==''?$last:$first); $ins->bindValue(':email',$em); $ins->bindValue(':kid',$kid); $ins->execute(); $imported++; }
				$libGlobal->notificationTexts[] = 'Import: ' . $imported . ' importiert, ' . $skipped . ' übersprungen.';
			}
		}

		// Panel ausgeben (immer sichtbar bei aktiviertem Keycloak)
		echo '<div class="panel panel-default">';
		echo '<div class="panel-body">';
		echo '<h3 class="mt-0">Keycloak Sync</h3>';
		if(!$kcAdminOk){
			echo '<div class="alert alert-warning">Keycloak-Adminzugriff nicht verfügbar. Prüfe keycloakClientSecret und Service-Account.</div>';
		}
		$disabled = (!$canAdminPerson || !$kcAdminOk) ? ' disabled="disabled" aria-disabled="true"' : '';
		echo '<form action="index.php?pid=intranet_admin_persons" method="post" class="form-inline">';
		echo '<input type="hidden" name="kc_action" value="scan" />';
		echo '<div class="checkbox" style="margin-right:10px">';
		echo '<label><input type="checkbox" name="kc_create_missing" value="1"' . ($disabled?' disabled="disabled"':'') . ' /> Fehlende Keycloak-Nutzer automatisch anlegen</label>';
		echo '</div> ';
		echo '<button type="submit" class="btn btn-primary"'.$disabled.'><i class="fa fa-refresh" aria-hidden="true"></i> Sync starten</button>';
		if(!$canAdminPerson){ echo '<p class="help-block mt-2">Hinweis: Für den Sync sind Internetwarte bzw. Datenpflegewarte berechtigt.</p>'; }
		echo '</form>';
		if(isset($GLOBALS['kc_remote_new_list_admin']) && is_array($GLOBALS['kc_remote_new_list_admin']) && count($GLOBALS['kc_remote_new_list_admin'])>0){
			echo '<hr />';
			echo '<h4>In Keycloak vorhanden, lokal nicht erfasst</h4>';
			echo '<form action="index.php?pid=intranet_admin_persons" method="post">';
			echo '<input type="hidden" name="kc_action" value="import" />';
			echo '<div class="table-responsive">';
			echo '<table class="table table-striped">';
			echo '<thead><tr><th></th><th>Vorname</th><th>Nachname</th><th>E-Mail</th><th>Keycloak-ID</th></tr></thead><tbody>';
			foreach($GLOBALS['kc_remote_new_list_admin'] as $ru){
				$fn = $libString->protectXSS($ru['firstName']);
				$ln = $libString->protectXSS($ru['lastName']);
				$em = $libString->protectXSS($ru['email']);
				$kid = $libString->protectXSS($ru['id']);
				echo '<tr>';
				echo '<td><input type="checkbox" name="kc_import_ids[]" value="'.$kid.'"'.($canAdminPerson?'':' disabled="disabled"').' /></td>';
				echo '<td>'.$fn.'</td><td>'.$ln.'</td><td>'.$em.'</td><td><code>'.$kid.'</code></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
			echo '</div>';
			echo '<button type="submit" class="btn btn-success"'.($canAdminPerson?'':' disabled="disabled" aria-disabled="true"').'><i class="fa fa-download" aria-hidden="true"></i> Ausgewählte importieren</button>';
			if(!$canAdminPerson){ echo '<p class="help-block mt-2">Hinweis: Import-Aktionen sind Internetwarten bzw. Datenpflegewarten vorbehalten.</p>'; }
			echo '</form>';
		}
		echo '</div>';
		echo '</div>';
	}

	echo '<div class="panel panel-default">';
	echo '<div class="panel-body">';
	echo '<form action="index.php?pid=intranet_admin_persons" method="post" class="form-inline">';
	echo '<fieldset>';
	echo '<div class="form-group">';

	echo '<label class="sr-only" for="sortierung">Sortierung</label>';
	echo '<select id="orderby" name="orderby" class="form-control" onchange="this.form.submit()">';
	echo '<option value="0" ';

	if (isset($_POST['orderby']) && $_POST['orderby'] == 0){
		echo 'selected="selected"';
	}

	echo '>Receptionssemester</option>';
	echo '<option value="1" ';

	if (isset($_POST['orderby']) && $_POST['orderby'] == 1){
		echo 'selected="selected"';
	}

	echo '>Name</option>';
	echo '<option value="2" ';

	if (isset($_POST['orderby']) && $_POST['orderby'] == 2){
		echo 'selected="selected"';
	}

	echo '>Gruppe</option>';
	echo '<option value="3" ';

	if (isset($_POST['orderby']) && $_POST['orderby'] == 3){
		echo 'selected="selected"';
	}

	echo '>Id</option>';
	echo '</select> ';

	$libForm->printSubmitButtonInline('Sortieren');

	echo '</div>';
	echo '</fieldset>';
	echo '</form>';
	echo '</div>';
	echo '</div>';


	echo '<div class="panel panel-default">';
	echo '<div class="panel-body">';

	echo '<table class="table table-condensed table-striped table-hover">';
	echo '<thead>';
	echo '<tr><th>Id</th><th>Präfix</th><th>Name</th><th>Suffix</th><th>Vorname</th><th>Gruppe</th><th>Status</th><th>Reception</th><th></th></tr>';
	echo '</thead>';

	$stmt = $libDb->prepare('SELECT * FROM base_person ORDER BY ' .$order);
	$stmt->execute();

	while($row = $stmt->fetch(PDO::FETCH_ASSOC)){
		echo '<tr>';
		echo '<td>' .$row['id']. '</td>';
		echo '<td>' .$row['praefix']. '</td>';
		echo '<td>' .$row['name']. '</td>';
		echo '<td>' .$row['suffix']. '</td>';
		echo '<td>' .$row['vorname']. '</td>';
		echo '<td>' .$row['gruppe']. '</td>';
		echo '<td>' .$row['status']. '</td>';
		echo '<td>' .$row['semester_reception']. '</td>';
		echo '<td class="tool-column">';
		echo '<a href="index.php?pid=intranet_admin_person&amp;id=' .$row['id']. '">';
		echo '<i class="fa fa-cog" aria-hidden="true"></i>';
		echo '</a>';
		echo '</td>';
		echo '</tr>';
	}

	echo '</table>';

	echo '</div>';
	echo '</div>';
}
