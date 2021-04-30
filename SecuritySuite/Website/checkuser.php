<!--
Jordan Laing
15009237
30/11/2020
checkuser.php - Checks that entered credentials are correct & signs a user into their account
-->

<?php
session_start();
?>


<?php

	//include details & functions stored within the 'DbConnect.php' document
	include('DbConnect.php');


	$scriptCheck = $_POST['scriptCheck'];
	$headerLink = "Location:login.php";
	$returnLink = ("<button onclick=\"location.href='login.php'\">Return to login page</button>");


	if(isset($_POST['email'])){
		$checkEmail = trim($_POST['email']);
		$checkPassword = trim($_POST['password']);
		
		if($checkEmail != "" && $checkPassword !=""){
			try{
				$query = "select * from users where email =:email";
				$stmt = $db->prepare($query);
				$stmt->bindParam('email', $checkEmail, PDO::PARAM_STR);
				$stmt->execute();
				$count = $stmt->rowCount();
				$row = $stmt->fetch(PDO::FETCH_ASSOC);
				if($count == 1 && !empty($row)) {
					$dbUID = $row['userID'];
					$dbUser = $row['userName'];
					$dbPass = $row['passwd'];
				
					if(password_verify($checkPassword, $dbPass)) {
						$_SESSION["userID"] = $dbUID;
						$_SESSION["username"] = $dbUser;
						header("Location:index.php");
					} else {
						$displayMessage = "Incorrect Password";
						returnUserMessage($displayMessage, $scriptCheck, $headerLink, $returnLink);
					}; 
				} else {
						$displayMessage = "Invalid email or password.";
						returnUserMessage($displayMessage, $scriptCheck, $headerLink, $returnLink);
				};
			} catch (PDOException $e) {
				echo "Error : ".$e->getMessage();
			};
		} else {
			$displayMessage = "Both fields are required to log in.";
			returnUserMessage($displayMessage, $scriptCheck, $headerLink, $returnLink);
		};
	};



	
	//display a passed message to the user
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