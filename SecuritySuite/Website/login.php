<!--
Jordan Laing
15009237
18/03/2021
login.php - Contains Sign in form
-->

<?php
session_start();
?>

<!DOCTYPE html>
<html>
	<head>
	
		<!--Allow viewport scaling-->
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		
		<!--Set tab header-->
		<title>Login | Security Suite</title>
		
		<!-- Link to the CSS file that drives the page formatting/style -->
		<link href="jomanji_style.css" type="text/css" rel="stylesheet" />
		
		<!--Script tag containing the JavaScript functions used on this page</script>-->
		<script src="client_functions.js"></script>
		
		<?php 
			//If an active session is detected, redirect the user to the index.php page
			if(isset($_SESSION["userID"])) {
			
				header("Location:index.php");
			};
		?>
	</head>
	
	<body onload="displayAlert()">

	<div class="PageContents">
		<div class="MainBody">
				
			<div class="SignInForm">
				
				<img id="signInLogo" src="img/logo.png" alt="client_logo.png">
				<br>
				<h1>Security Scanning Tool</h1>
				<br>
				<h2>Sign In</h2>
				<br>
				
				<form id='signInForm' method="post" action="checkuser.php">

					<input type="email" id="inputEmail" name="email" placeholder="Email" size="25" required autofocus>
					<br>
					<input type="password" id="inputPassword" name="password" placeholder="Password" size="25" required>
					<br>
					<input type='hidden' id='scriptCheckSignIn' name='scriptCheck' value='N'>
					<br>
					<button class="CapButton" type="submit">Sign In</button>
				</form>
			</div>
		</div>

		
		<footer>
			
			<script>
					
				scriptCheck('scriptCheckSignIn');
			</script>
		</footer>	
	</body>
</html> 