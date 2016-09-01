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

if(!is_object($libGlobal))
	exit();


$stmtCount = $libDb->prepare('SELECT COUNT(*) AS number FROM base_veranstaltung WHERE intern = 0 AND datum > NOW()');
$stmtCount->execute();
$stmtCount->bindColumn('number', $numberOfNextEvents);
$stmtCount->fetch();

$semesterCoverAvailable = false;

if($libModuleHandler->moduleIsAvailable('mod_internet_semesterprogramm')){
	$semesterCoverString = $libTime->getSemesterCoverString($libGlobal->semester);
	$semesterCoverAvailable = $semesterCoverString != '';
}

if($semesterCoverAvailable || $numberOfNextEvents > 0){
	echo '<section class="nextevents-box">';
	echo '<div class="container">';

	echo '<div class="row">';
	echo '<div class="col-lg-8 col-lg-offset-2 text-center">';
	echo '<h1 class="section-heading">Nächste Veranstaltungen</h1>';
	echo '<hr>';
	echo '</div>';
	echo '</div>';

	echo '<div class="row">';

	if($numberOfNextEvents > 0){
		if($semesterCoverAvailable){
			$maxNumberOfEvents = 2;
		} else {
			$maxNumberOfEvents = 3;
		}

		$stmt = $libDb->prepare('SELECT id, titel, datum, status, ort, fb_eventid, intern FROM base_veranstaltung WHERE intern = 0 AND datum > NOW() ORDER BY datum LIMIT 0,' .$maxNumberOfEvents);
		$stmt->execute();

		while($row = $stmt->fetch(PDO::FETCH_ASSOC)){
			echo '<div class="col-sm-4">';
			echo '<div class="thumbnail">';
			echo '<div class="caption">';
			echo '<h3><a href="index.php?pid=semesterprogramm_event&amp;eventid=' .$row['id']. '">';

			printVeranstaltungTitle($row);

			echo '</a></h3>';

			printVeranstaltungDateTime($row);

			if ($row['ort'] != ''){
				echo '<address>' .$row['ort']. '</address>';
			}

			echo '<p>Status: ' .$libEvent->getStatusString($row['status']). '</p>';
			echo '<hr />';
			echo '<p>';

			if(!$libEvent->isFacebookEvent($row)){
				$libEvent->printFacebookShareButton($row['id']);
			}

			$libEvent->printTwitterShareButton($row['id']);
			echo '</p>';

			echo '</div>';
			echo '</div>';
			echo '</div>';
		}
	}

	if($semesterCoverAvailable){
		echo '<div class="col-sm-4">';
		echo '<div class="thumbnail">';
		echo '<div class="semestercoverBox center-block">';
		echo '<a href="index.php?pid=semesterprogramm&amp;semester=' .$libGlobal->semester. '">';
		echo $semesterCoverString;
		echo '</a>';
		echo '</div>';

		echo '<div class="caption">';
		echo '<h3><i class="fa fa-calendar" aria-hidden="true"></i> <a href="index.php?pid=semesterprogramm&amp;semester=' .$libGlobal->semester. '">Semesterprogramm</a></h3>';
		echo '<p>Weitere Veranstaltungen im <a href="index.php?pid=semesterprogramm&amp;semester=' .$libGlobal->semester. '">Semesterprogramm ' .$libTime->getSemesterString($libGlobal->semester). '</a></p>';
		echo '</div>';

		echo '</div>';
		echo '</div>';
	}

	echo '</div>';
	echo '</div>';
	echo '</section>';
}
