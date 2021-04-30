<!--
Jordan Laing
15009237
26/03/2021
accountmodify.php - Change account password
-->
<?php
session_start();
?>

<?php

	include("DbConnect.php");
	
	$headerLink = "Location:account.php";
	$returnLink = ("<button onclick=\"location.href='account.php'\">Return to account modification page</button>");
	
	$scriptCheck = $_POST['scriptCheck'];
		
	$userID = $_SESSION["userID"];
	include ("DbConnect.php");
		
	$scan_stmt = $db->query("SELECT * FROM users WHERE userID = $userID")->fetchAll();

	foreach($scan_stmt as $row){
		$userpw = $row[passwd];
	}

	$checkPass = $_POST['currentpassword'];	
	$pass = $_POST['newpassword'];
	$passConf = $_POST['confirmpassword'];
	
	if(password_verify($checkPass ,$userpw)){
		
		if ($pass == $passConf) {
			$hashedPass = password_hash($pass, PASSWORD_DEFAULT);
			
			echo $hashedPass;
//			$update_stmt = $db->query("UPDATE 'users' SET 'passwd' = $hashedPass WHERE 'userID' = $userID");
			$update_stmt = $db->prepare("UPDATE users set passwd = ':password' where userID = ':userID'");
            $update_stmt->execute(array(':userID' => $userID, ':password' => $hashedPass));

			echo "Update failed";
			$displayMessage = "Password successfully updated";
			returnUserMessage($displayMessage, $scriptCheck, $headerLink, $returnLink);
		} else {

			$displayMessage = "Password and confirm password do not match";
			returnUserMessage($displayMessage, $scriptCheck, $headerLink, $returnLink);
		};
	} else {
				
		$displayMessage = "Incorrect password";
		returnUserMessage($displayMessage, $scriptCheck, $headerLink, $returnLink);
	};
	
	
	function returnUserMessage($displayMessage, $scriptCheck, $headerLink, $returnLink) {
		
		if($scriptCheck=="Y"){
			
			setcookie('Site_Message',$displayMessage,time()+10);
			header($headerLink);
		} else {
			
			echo $displayMessage;
			echo "<br>";
			echo $returnLink;
		};
	};
?>