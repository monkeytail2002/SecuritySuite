<!--
Jordan Laing
15009237
19/03/2021
jomanjifunctions.php - Contains php functions used on multiple pages
-->

<?php
session_start();
?>

<?php
	
	//If there is no active session, redirect the user to the login.php page
	function checkActiveSession() {
		
		if(isset($_SESSION["userID"])) {
			
		} else {
			
			$displayMessage = "Please log in to continue";
			returnUserMessage($displayMessage, "Location:login.php");
		};
	};
	
	//Display a passed message to the user
	function returnUserMessage($displayMessage, $headerLink) {
		
		setcookie('Site_Message',$displayMessage,time()+10);
		header($headerLink);
	};
	
	function fetchAccountDetails() {
		
		include ("DbConnect.php");
		
		$userID = $_SESSION["userID"];
		$scan_stmt = $db->query("SELECT * FROM users WHERE userID = $userID")->fetchAll();

		foreach($scan_stmt as $row){
			//Fill in basic account details
			echo "<p><b>Username</b>: ".$row[userName]."</p>";
			echo "<p><b>Email Address</b>: ".$row[email]."</p>";
		}
			
	};
?>