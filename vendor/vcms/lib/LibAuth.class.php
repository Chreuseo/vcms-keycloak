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

namespace vcms;

use PDO;

class LibAuth{
	var $id;
	var $anrede;
	var $titel;
	var $praefix;
	var $vorname;
	var $suffix;
	var $nachname;

	var $gruppe;
	var $aemter = array();
	var $possibleGruppen = array();

	var $isLoggedIn = false;
	var $authSource = 'local'; // neu

	/*
	* tries to login with email and password
	*/
	function login($email, $password){
		global $libGlobal, $libDb, $libPerson, $libTime, $libSecurityManager, $libString;

		$email = trim(strtolower($email));
		$password = trim($password);

		//clean memory
		$this->id = '';
		$this->anrede = '';
		$this->titel = '';
		$this->praefix = '';
		$this->vorname = '';
		$this->suffix = '';
		$this->nachname = '';

		$this->gruppe = '';
		$this->aemter = array();
		$this->possibleGruppen = array();

		$this->isLoggedIn = false;

		//collect potential valid groups
		$stmt = $libDb->prepare('SELECT bezeichnung FROM base_gruppe');
		$stmt->execute();

		while($row = $stmt->fetch(PDO::FETCH_ASSOC)){
			if($row['bezeichnung'] != 'T' && $row['bezeichnung'] != 'X' && $row['bezeichnung'] != 'V'){
				$this->possibleGruppen[] = $row['bezeichnung'];
			}
		}

		/*
		* check for problem cases
		*/

		//1. no email given
		if($email == ''){
			$libGlobal->errorTexts[] = 'Die E-Mail-Adresse fehlt.';
			return false;
		}

		//2. no password given
		if($password == ''){
			$libGlobal->errorTexts[] = 'Das Passwort fehlt.';
			return false;
		}

		$stmt = $libDb->prepare('SELECT id, anrede, titel, praefix, vorname, suffix, gruppe, name, email, password_hash FROM base_person WHERE email=:email');
		$stmt->bindValue(':email', $email);
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);

		//3. no user with that email address given
		if(!is_array($row) || !isset($row['id']) || !is_numeric($row['id']) || !($row['id'] > 0)){
			//error message has to be imprecise
			$libGlobal->errorTexts[] = 'E-Mail-Adresse oder Passwort falsch.';
			return false;
		}

		//4. user is in an invalid group
		if(!in_array($row['gruppe'], $this->possibleGruppen)){
			$libGlobal->errorTexts[] = 'Gruppe falsch.';
			return false;
		}

		//5. missing password hash
		if(trim($row['password_hash'] == '')){
			$libGlobal->errorTexts[] = 'In der Datenbank ist kein Passwort-Hash vorhanden.';
			return false;
		}

		//6. check number of mistaken login attempts; brute force prevention
		$stmt = $libDb->prepare('SELECT COUNT(*) AS number FROM sys_log_intranet WHERE mitglied=:mitglied AND aktion=2 AND DATEDIFF(NOW(), datum) = 0');
		$stmt->bindValue(':mitglied', $row['id'], PDO::PARAM_INT);
		$stmt->execute();
		$stmt->bindColumn('number', $numberOfMistakenLoginsToday);
		$stmt->fetch();

		if($numberOfMistakenLoginsToday > 0){
			$stmt = $libDb->prepare('SELECT datum FROM sys_log_intranet WHERE mitglied=:mitglied AND aktion=2 AND DATEDIFF(NOW(), datum) = 0 ORDER BY datum DESC LIMIT 0,1');
			$stmt->bindValue(':mitglied', $row['id'], PDO::PARAM_INT);
			$stmt->execute();
			$stmt->bindColumn('datum', $lastMistakenLoginToday);
			$stmt->fetch();

			$nextPossibleLoginTimeStamp = strtotime($lastMistakenLoginToday) + pow(2, $numberOfMistakenLoginsToday);
			$secondsToNextPossibleLogin = $nextPossibleLoginTimeStamp - time();

			if($secondsToNextPossibleLogin > 0){
				if($secondsToNextPossibleLogin < 120){
					$libGlobal->errorTexts[] = 'Dieses Konto ist für die nächsten ' .$secondsToNextPossibleLogin. ' Sekunden gesperrt, da zu viele erfolglose Anmeldeversuche unternommen wurden.';
				} else {
					$minutesToNextPossibleLogin = floor($secondsToNextPossibleLogin / 60);
					$libGlobal->errorTexts[] = 'Dieses Konto ist für die nächsten ' .$minutesToNextPossibleLogin. ' Minuten gesperrt, da zu viele erfolglose Anmeldeversuche unternommen wurden.';
				}

				return false;
			}
		}

		//7. check password
		if($this->checkPassword($password, $row['password_hash'])){
			//a. login successful
			$this->isLoggedIn = true;

			$this->id = $row['id'];
			$this->anrede = $row['anrede'];
			$this->titel = $row['titel'];
			$this->praefix = $row['praefix'];
			$this->vorname = $row['vorname'];
			$this->suffix = $row['suffix'];
			$this->nachname = $row['name'];
			$this->gruppe = $row['gruppe'];

			//b. determine functions
			$stmt = $libDb->prepare('SELECT * FROM base_semester WHERE semester=:semester OR semester=:semester_next');
			$stmt->bindValue(':semester', $libTime->getSemesterName());
			$stmt->bindValue(':semester_next', $libTime->getFollowingSemesterName());
			$stmt->execute();

			//for all semesters
			while($semesterRow = $stmt->fetch(PDO::FETCH_ASSOC)){
				$possibleAemter = $libSecurityManager->getPossibleAemter();

				//for all functions
				foreach($possibleAemter as $amt){
					//does the member have the function in the semester?
					if($semesterRow[$amt] == $row['id']){
						//save this function
						$this->aemter[] = $amt;
					}
				}
			}

			//for the last 20 semesters
			$semesterIterator = $libTime->getSemesterName();

			for($i=0; $i<20; $i++){
				$semesterIterator = $libTime->getPreviousSemesterNameOfSemester($semesterIterator);

				//select the internetwart in that semester
				$stmt = $libDb->prepare('SELECT internetwart FROM base_semester WHERE semester=:semester');
				$stmt->bindValue(':semester', $semesterIterator);
				$stmt->execute();
				$stmt->bindColumn('internetwart', $internetwart);
				$stmt->fetch();

				//if there is an internetwart given
				if($internetwart){
					//if the authenticating user is this internetwart
					if($internetwart == $row['id']){
						//save this function
						$this->aemter[] = 'internetwart';
					}

					//we only want to do this for the most recent internetwart -> break
					break;
				}
			}

			//remove redundant functions from multiple semesters
			$this->aemter = array_unique($this->aemter);

			//c. log successful login attempt
			$stmt = $libDb->prepare('INSERT INTO sys_log_intranet (mitglied, aktion, datum, punkte, ipadresse) VALUES (:mitglied, :aktion, NOW(), :punkte, :ipadresse)');
			$stmt->bindValue(':mitglied', $row['id'], PDO::PARAM_INT);
			$stmt->bindValue(':aktion', 1, PDO::PARAM_INT);
			$stmt->bindValue(':punkte', 0, PDO::PARAM_INT);
			$stmt->bindValue(':ipadresse', $_SERVER['REMOTE_ADDR']);
			$stmt->execute();

			$libPerson->setIntranetActivity($row['id'], 1, 1);

			return true;
		}

		//8. log mistaken login attempt
		$stmt = $libDb->prepare('INSERT INTO sys_log_intranet (mitglied, aktion, datum, punkte, ipadresse) VALUES (:mitglied, :aktion, NOW(), :punkte, :ipadresse)');
		$stmt->bindValue(':mitglied', $row['id'], PDO::PARAM_INT);
		$stmt->bindValue(':aktion', 2, PDO::PARAM_INT);
		$stmt->bindValue(':punkte', 0, PDO::PARAM_INT);
		$stmt->bindValue(':ipadresse', $_SERVER['REMOTE_ADDR']);
		$stmt->execute();

		//error message has to be imprecise
		$libGlobal->errorTexts[] = 'E-Mail-Adresse oder Passwort falsch.';
		return false;
	}

	// --- Keycloak JWT Login (neu) -------------------------------------------
	function loginWithKeycloakJwt($jwt){
		global $libGlobal, $libDb, $libConfig, $libTime, $libSecurityManager, $libPerson;
		if(!$this->isKeycloakEnabled()) return false;
		$jwt = trim($jwt);
		if($jwt==='') return false;

		$this->ensureKeycloakColumnExists();
		$parts = explode('.', $jwt);
		if(count($parts) !== 3){ $libGlobal->errorTexts[]='Ungültiges Token.'; return false; }
		list($h,$p,$s) = $parts;
		$header = json_decode($this->base64UrlDecode($h), true);
		$payload = json_decode($this->base64UrlDecode($p), true);
		$signature = $this->base64UrlDecode($s);
		if(!is_array($header) || !is_array($payload)){ $libGlobal->errorTexts[]='Ungültiges Token.'; return false; }
		if(($header['alg']??'') !== 'RS256'){ $libGlobal->errorTexts[]='Nicht unterstützter Algorithmus.'; return false; }

		$now = time();
		if(isset($payload['exp']) && $now > $payload['exp']){ $libGlobal->errorTexts[]='Token abgelaufen.'; return false; }
		if(isset($payload['nbf']) && $now + 30 < $payload['nbf']){ $libGlobal->errorTexts[]='Token noch nicht gültig.'; return false; }
		if(!$this->verifyIssuerAudience($payload)){ $libGlobal->errorTexts[]='Issuer oder Audience ungültig.'; return false; }

		// Signatur prüfen: bevorzugt JWKS per kid, dann Fallback auf statischen Public Key
		$verified = false; $signingInput = $h.'.'.$p; $kid = isset($header['kid']) ? $header['kid'] : '';
		if($kid !== ''){
			$pubFromJwks = $this->getKeycloakPemByKid($kid);
			if($pubFromJwks){ $verified = $this->verifyRs256($signingInput, $signature, $pubFromJwks); }
		}
		if(!$verified){
			$publicKey = $this->getKeycloakPublicKey();
			if(!$publicKey){ $libGlobal->errorTexts[]='Keycloak Public Key fehlt.'; return false; }
			if(!$this->verifyRs256($signingInput, $signature, $publicKey)){ $libGlobal->errorTexts[]='Token Signatur ungültig.'; return false; }
		}

		$keycloakId = $payload['sub'] ?? null;
		$email = isset($payload['email']) ? strtolower(trim($payload['email'])) : '';
		$vorname = $payload['given_name'] ?? '';
		$nachname = $payload['family_name'] ?? ($payload['name'] ?? '');
		if(!$keycloakId || $email===''){ $libGlobal->errorTexts[]='Erforderliche Claims fehlen.'; return false; }

		// mögliche Gruppen laden
		$this->possibleGruppen = array();
		$stmt = $libDb->prepare('SELECT bezeichnung FROM base_gruppe');
		$stmt->execute();
		while($r = $stmt->fetch(PDO::FETCH_ASSOC)){
			if($r['bezeichnung']!='T' && $r['bezeichnung']!='X' && $r['bezeichnung']!='V') $this->possibleGruppen[] = $r['bezeichnung'];
		}
		$defaultGroup = $libConfig->keycloakDefaultGroup ?? '';
		if($defaultGroup === '' && count($this->possibleGruppen)>0){
			$defaultGroup = $this->possibleGruppen[0];
		}
		// NEU: Fallback, falls konfigurierte Default-Gruppe nicht existiert
		if($defaultGroup !== '' && !in_array($defaultGroup, $this->possibleGruppen) && count($this->possibleGruppen)>0){
			$defaultGroup = $this->possibleGruppen[0];
		}

		// 1) anhand keycloak_id
		$stmt = $libDb->prepare('SELECT id, anrede, titel, praefix, vorname, suffix, gruppe, name, email FROM base_person WHERE keycloak_id = :kid');
		$stmt->bindValue(':kid', $keycloakId); $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
		if(!$row){
			// 2) anhand email
			$stmt = $libDb->prepare('SELECT id, anrede, titel, praefix, vorname, suffix, gruppe, name, email FROM base_person WHERE email = :email');
			$stmt->bindValue(':email', $email); $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
			if($row){
				$upd = $libDb->prepare('UPDATE base_person SET keycloak_id = :kid WHERE id = :id');
				$upd->bindValue(':kid',$keycloakId); $upd->bindValue(':id',$row['id'],PDO::PARAM_INT); $upd->execute();
			}else{
				if($defaultGroup===''){ $libGlobal->errorTexts[]='Keine gültige Standardgruppe konfiguriert.'; return false; }
				$ins = $libDb->prepare('INSERT INTO base_person (anrede, titel, praefix, vorname, suffix, gruppe, name, email, password_hash, keycloak_id) VALUES ("","","", :vorname, "", :gruppe, :name, :email, "", :kid)');
				$ins->bindValue(':vorname',$vorname);
				$ins->bindValue(':gruppe',$defaultGroup);
				$ins->bindValue(':name',$nachname ?: $vorname);
				$ins->bindValue(':email',$email);
				$ins->bindValue(':kid',$keycloakId);
				$ins->execute();
				$newId = $libDb->lastInsertId();
				$stmt = $libDb->prepare('SELECT id, anrede, titel, praefix, vorname, suffix, gruppe, name, email FROM base_person WHERE id=:id');
				$stmt->bindValue(':id',$newId,PDO::PARAM_INT); $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
			}
		}
		if(!$row || !isset($row['id'])){ $libGlobal->errorTexts[]='Keycloak Benutzer konnte nicht ermittelt werden.'; return false; }
		if(!in_array($row['gruppe'], $this->possibleGruppen)){ $libGlobal->errorTexts[]='Benutzergruppe nicht erlaubt.'; return false; }

		// Benutzer Zustand setzen
		$this->id = $row['id'];
		$this->anrede = $row['anrede'];
		$this->titel = $row['titel'];
		$this->praefix = $row['praefix'];
		$this->vorname = $row['vorname'];
		$this->suffix = $row['suffix'];
		$this->nachname = $row['name'];
		$this->gruppe = $row['gruppe'];
		$this->isLoggedIn = true;
		$this->authSource = 'keycloak';

		// Ämter (aktuelles + folgendes Semester)
		$stmt = $libDb->prepare('SELECT * FROM base_semester WHERE semester=:sem OR semester=:sem2');
		$stmt->bindValue(':sem',$libTime->getSemesterName());
		$stmt->bindValue(':sem2',$libTime->getFollowingSemesterName());
		$stmt->execute();
		while($semRow = $stmt->fetch(PDO::FETCH_ASSOC)){
			$possibleAemter = $libSecurityManager->getPossibleAemter();
			foreach($possibleAemter as $amt){ if(isset($semRow[$amt]) && $semRow[$amt]==$row['id']) $this->aemter[]=$amt; }
		}
		$this->aemter = array_unique($this->aemter);

		// Historischer Internetwart (wie lokaler Login)
		$semesterIterator = $libTime->getSemesterName();
		for($i=0;$i<20;$i++){
			$semesterIterator = $libTime->getPreviousSemesterNameOfSemester($semesterIterator);
			$stmt2 = $libDb->prepare('SELECT internetwart FROM base_semester WHERE semester=:sem');
			$stmt2->bindValue(':sem',$semesterIterator); $stmt2->execute(); $stmt2->bindColumn('internetwart',$internetwart); $stmt2->fetch();
			if($internetwart){ if($internetwart==$row['id']) $this->aemter[]='internetwart'; break; }
		}
		$this->aemter = array_unique($this->aemter);

		// Log
		try { $log=$libDb->prepare('INSERT INTO sys_log_intranet (mitglied, aktion, datum, punkte, ipadresse) VALUES (:m,1,NOW(),0,:ip)'); $log->bindValue(':m',$row['id'],PDO::PARAM_INT); $log->bindValue(':ip',$_SERVER['REMOTE_ADDR']??''); $log->execute(); }catch(\Exception $e){}
		if(isset($libPerson)) $libPerson->setIntranetActivity($row['id'],1,1);
		return true;
	}

	function loginWithKeycloakAuthCode($code, $redirectUri){
		global $libGlobal, $libConfig;
		if(!$this->isKeycloakEnabled()) return false;
		$code = trim($code);
		$redirectUri = trim($redirectUri);
		if($code==='') return false;

		// Konfiguration ermitteln
		$issuer = '';
		if(isset($libConfig->keycloakAllowedIssuers) && is_array($libConfig->keycloakAllowedIssuers) && count($libConfig->keycloakAllowedIssuers)>0){
			$issuer = $libConfig->keycloakAllowedIssuers[0];
		}
		if($issuer===''){ $libGlobal->errorTexts[]='Issuer nicht konfiguriert.'; return false; }
		$clientId = '';
		if(isset($libConfig->keycloakClientId) && $libConfig->keycloakClientId!=='') $clientId=$libConfig->keycloakClientId;
		elseif(isset($libConfig->keycloakAllowedAudiences) && is_array($libConfig->keycloakAllowedAudiences) && count($libConfig->keycloakAllowedAudiences)>0) $clientId=$libConfig->keycloakAllowedAudiences[0];
		if($clientId===''){ $libGlobal->errorTexts[]='Client-ID nicht konfiguriert.'; return false; }
		$clientSecret = '';
		if(isset($libConfig->keycloakClientSecret) && $libConfig->keycloakClientSecret!=='') $clientSecret = $libConfig->keycloakClientSecret;
		$clientAuthMethod = 'post';
		if(isset($libConfig->keycloakClientAuthMethod) && in_array(strtolower($libConfig->keycloakClientAuthMethod), array('post','basic'))){
			$clientAuthMethod = strtolower($libConfig->keycloakClientAuthMethod);
		}

		$tokenUrl = rtrim($issuer,'/').'/protocol/openid-connect/token';

		// POST-Felder (Basis)
		$baseFields = array(
			'grant_type' => 'authorization_code',
			'code' => $code,
			'client_id' => $clientId,
			'redirect_uri' => $redirectUri
		);
		// PKCE Code Verifier aus Session
		if(session_status()===PHP_SESSION_NONE) session_start();
		if(isset($_SESSION['keycloak_pkce_verifier']) && $_SESSION['keycloak_pkce_verifier']!==''){
			$baseFields['code_verifier'] = $_SESSION['keycloak_pkce_verifier'];
		}

		// Request als kleiner Helfer
		$doTokenRequest = function($authMethod) use ($tokenUrl, $baseFields, $clientId, $clientSecret){
			$fields = $baseFields;
			$headers = array('Content-Type: application/x-www-form-urlencoded');
			if($clientSecret !== ''){
				if($authMethod === 'basic'){
					$headers[] = 'Authorization: Basic ' . base64_encode($clientId . ':' . $clientSecret);
				} else {
					$fields['client_secret'] = $clientSecret;
				}
			}
			$ch = curl_init($tokenUrl);
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($fields, '', '&', PHP_QUERY_RFC3986));
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($ch, CURLOPT_TIMEOUT, 15);
			$response = curl_exec($ch);
			$curlErr = curl_error($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
			curl_close($ch);
			return array($httpCode, $response, $curlErr);
		};

		// Erster Versuch mit konfigurierter Methode
		list($httpCode, $response, $curlErr) = $doTokenRequest($clientAuthMethod);
		// Automatischer Fallback bei 401 und vorhandenem Secret
		if($httpCode === 401 && $clientSecret !== ''){
			$alt = ($clientAuthMethod === 'basic') ? 'post' : 'basic';
			list($httpCode, $response, $curlErr) = $doTokenRequest($alt);
		}

		if(isset($_SESSION['keycloak_pkce_verifier'])) unset($_SESSION['keycloak_pkce_verifier']);
		if($response===false){ $libGlobal->errorTexts[]='Keycloak Token-Anfrage fehlgeschlagen: '.$curlErr; return false; }
		$data = json_decode($response, true);
		if($httpCode!==200){
			$err = isset($data['error_description']) ? $data['error_description'] : (isset($data['error'])?$data['error']:'Unbekannter Fehler');
			// Zusatzhinweis bei 401: deutet meist auf einen als Confidential konfigurierten Client hin. Entweder Secret in systemconfig.php setzen (keycloakClientSecret) und keycloakClientAuthMethod=post|basic passend wählen oder den Client in Keycloak auf Public umstellen.
			if($httpCode===401){
				$hint = ' Hinweis: 401 weist häufig auf einen als Confidential konfigurierten Client hin. Entweder Secret in systemconfig.php setzen (keycloakClientSecret) und keycloakClientAuthMethod=post|basic passend wählen oder den Client in Keycloak auf Public umstellen.';
				$err .= $hint;
			}
			$libGlobal->errorTexts[]='Token konnte nicht abgeholt werden (HTTP '.$httpCode.'): '.$err;
			return false;
		}
		$accessToken = isset($data['access_token']) ? $data['access_token'] : '';
		if($accessToken===''){ $libGlobal->errorTexts[]='Kein access_token im Token-Response.'; return false; }
		return $this->loginWithKeycloakJwt($accessToken);
	}


	private function isKeycloakEnabled(){ global $libConfig; return isset($libConfig->keycloakEnabled) && $libConfig->keycloakEnabled; }
	private function getKeycloakPublicKey(){ global $libConfig; if(isset($libConfig->keycloakPublicKey) && trim($libConfig->keycloakPublicKey)!=''){ $pk=trim($libConfig->keycloakPublicKey); if(strpos($pk,'BEGIN PUBLIC KEY')===false){ $pk="-----BEGIN PUBLIC KEY-----\n".$pk."\n-----END PUBLIC KEY-----"; } return $pk; } return null; }
	private function verifyIssuerAudience(array $payload){
		global $libConfig;
		if(!empty($libConfig->keycloakAllowedIssuers)){
			if(!isset($payload['iss']) || !in_array($payload['iss'],$libConfig->keycloakAllowedIssuers)) return false;
		}
		if(!empty($libConfig->keycloakAllowedAudiences)){
			$audOk = false;
			if(isset($payload['aud'])){
				$aud = $payload['aud'];
				if(is_string($aud)){
					$audOk = in_array($aud,$libConfig->keycloakAllowedAudiences);
				} elseif(is_array($aud)){
					foreach($aud as $a){ if(in_array($a,$libConfig->keycloakAllowedAudiences)){ $audOk=true; break; } }
				}
			}
			if(!$audOk && isset($payload['azp']) && in_array($payload['azp'],$libConfig->keycloakAllowedAudiences)){
				$audOk = true;
			}
			if(!$audOk) return false;
		}
		return true;
	}
	private function getIssuer(){
		global $libConfig;
		if(isset($libConfig->keycloakAllowedIssuers) && is_array($libConfig->keycloakAllowedIssuers) && count($libConfig->keycloakAllowedIssuers)>0){
			return rtrim($libConfig->keycloakAllowedIssuers[0], '/');
		}
		return null;
	}
	private function fetchKeycloakJwks($issuer){
		static $cache=null; static $ts=0;
		if($cache && (time()-$ts)<300) return $cache;
		$url = $issuer.'/protocol/openid-connect/certs';
		if(!function_exists('curl_init')) return null;
		$ch = curl_init($url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_TIMEOUT, 10);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: application/json'));
		$resp = curl_exec($ch);
		$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		curl_close($ch);
		if($resp!==false && $code===200){ $cache = json_decode($resp, true); $ts=time(); return $cache; }
		return null;
	}
	private function getKeycloakPemByKid($kid){
		$issuer = $this->getIssuer(); if(!$issuer) return null;
		$jwks = $this->fetchKeycloakJwks($issuer);
		if(!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) return null;
		foreach($jwks['keys'] as $jwk){
			if(!isset($jwk['kid']) || $jwk['kid']!==$kid) continue;
			if(isset($jwk['x5c']) && is_array($jwk['x5c']) && count($jwk['x5c'])>0){
				$certDerB64 = $jwk['x5c'][0];
				$pem = "-----BEGIN CERTIFICATE-----\n".$this->chunkSplit($certDerB64,64)."\n-----END CERTIFICATE-----";
				return $pem;
			}
			if(isset($jwk['n']) && isset($jwk['e'])){
				$pub = $this->rsaPemFromModExp($jwk['n'],$jwk['e']); if($pub) return $pub;
			}
		}
		return null;
	}
	private function chunkSplit($body,$chunklen){ $len=strlen($body); $out=''; for($i=0;$i<$len;$i+=$chunklen){ $out.=substr($body,$i,$chunklen)."\n"; } return rtrim($out,"\n"); }
	private function asn1Len($len){ if($len<0x80){ return chr($len);} $out=''; while($len>0){ $out=chr($len&0xFF).$out; $len>>=8;} return chr(0x80|strlen($out)).$out; }
	private function rsaPemFromModExp($nB64Url,$eB64Url){ $n=$this->base64UrlDecode($nB64Url); $e=$this->base64UrlDecode($eB64Url); if($n===false||$e===false) return null; $seq=function($d){return chr(0x30).$this->asn1Len(strlen($d)).$d;}; $int=function($d){ if(ord($d[0])>0x7f){ $d="\x00".$d;} return chr(0x02).$this->asn1Len(strlen($d)).$d;}; $bit=function($d){ return chr(0x03).$this->asn1Len(strlen($d)+1)."\x00".$d;}; $oid="\x06\x09".chr(0x2a).chr(0x86).chr(0x48).chr(0x86).chr(0xf7).chr(0x0d).chr(0x01).chr(0x01).chr(0x01); $alg=$seq($oid."\x05\x00"); $rsakey=$seq($int($n).$int($e)); $spki=$seq($alg.$bit($rsakey)); return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($spki),64,"\n")."-----END PUBLIC KEY-----"; }
	private function verifyRs256($data,$sig,$pub){ if(!function_exists('openssl_verify')) return false; $pubKeyRes=@openssl_pkey_get_public($pub); if(!$pubKeyRes) return false; $ok=openssl_verify($data,$sig,$pubKeyRes,OPENSSL_ALGO_SHA256)===1; @openssl_pkey_free($pubKeyRes); return $ok; }
	private function base64UrlDecode($d){ $r=strlen($d)%4; if($r){ $d.=str_repeat('=',4-$r);} return base64_decode(strtr($d,'-_','+/')); }
	private function ensureKeycloakColumnExists(){ global $libDb; try{ $c=$libDb->prepare("SHOW COLUMNS FROM base_person LIKE 'keycloak_id'"); $c->execute(); if(!$c->fetch(PDO::FETCH_ASSOC)){ $alt=$libDb->prepare("ALTER TABLE base_person ADD COLUMN keycloak_id VARCHAR(190) NULL DEFAULT NULL, ADD UNIQUE KEY idx_keycloak_id (keycloak_id)"); $alt->execute(); } }catch(\Exception $e){} }

	function encryptPassword($password){
		$phpassHasher = new \phpass\PasswordHash(12, FALSE);
		return $phpassHasher->HashPassword($password);
	}

	function savePassword($personId, $newPassword, $quiet = false, $checkIsValidPassword = true){
		global $libGlobal, $libDb;

		//1. validation of person id
		if(!is_numeric($personId)){
			return false;
		}

		//2. validation of password
		$newPassword = trim($newPassword);

		//a. empty password
		if($newPassword == ''){
			if(!$quiet){
				$libGlobal->errorTexts[] = 'Das neue Passwort ist leer.';
			}

			return false;
		}

		//b. invalid password
		if($checkIsValidPassword){
			if(!$this->isValidPassword($newPassword)){
				if(!$quiet){
					$libGlobal->errorTexts[] = 'Das neue Passwort ist nicht komplex genug. '. $this->getPasswordRequirements();
				}

				return false;
			}
		}

		//3. generate hash from password
		$passwdHash = $this->encryptPassword($newPassword);

		//4. save hash
		$stmt = $libDb->prepare('UPDATE base_person SET password_hash = :password_hash WHERE id = :id');
		$stmt->bindValue(':password_hash', $passwdHash);
		$stmt->bindValue(':id', $personId, PDO::PARAM_INT);
		$stmt->execute();

		if(!$quiet){
			$libGlobal->notificationTexts[] = 'Das Passwort wurde gespeichert.';
		}

		return true;
	}

	function checkPassword($password, $storedHash){
		$password = trim($password);
		$storedHash = trim($storedHash);

		// check by BCrypt
		if($password != '' && $storedHash != ''){
			$phpassHasher = new \phpass\PasswordHash(12, FALSE);
			return $phpassHasher->CheckPassword($password, $storedHash);
		}

		return false;
	}
	function checkPasswordForPerson($personId, $password){
		global $libDb;

		if(!is_numeric($personId)){
			return false;
		}

		$stmt = $libDb->prepare('SELECT password_hash FROM base_person WHERE id = :id');
		$stmt->bindValue(':id', $personId, PDO::PARAM_INT);
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);

		return $this->checkPassword($password, $row['password_hash']);
	}

	function isValidPassword($password){
		//min 1 Ziffer, min 1 Kleinbuchstabe, min 1 Großbuchstabe, kein Leerzeichen, min 10 Zeichen
		return preg_match("/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.*\s).{10,}$/", trim($password));
	}

	function getPasswordRequirements(){
		return 'Das Passwort muss aus mindestens 10 Zeichen bestehen, mit mindestens einer Ziffer, mindestens einem Kleinbuchstaben und mindestens einem Großbuchstaben. Leerzeichen sind nicht erlaubt.';
	}

	//-------------------------------------------------------------------------

	function getId(){
		return $this->id;
	}

	function getAnrede(){
		return $this->anrede;
	}

	function getTitel(){
		return $this->titel;
	}

	function getVorname(){
		return $this->vorname;
	}

	function getPraefix(){
		return $this->praefix;
	}

	function getNachname(){
		return $this->nachname;
	}

	function getSuffix(){
		return $this->suffix;
	}

	function getGruppe(){
		return $this->gruppe;
	}

	function getAemter(){
		return $this->aemter;
	}

	function isLoggedin(){
		if($this->isLoggedIn && is_numeric($this->id) &&
				$this->id > 0 && $this->gruppe != '' &&
				in_array($this->gruppe, $this->possibleGruppen)){
			return true;
		} else {
			return false;
		}
	}
}
