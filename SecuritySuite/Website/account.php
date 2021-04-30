<!--
Jordan Laing
15009237
26/03/2021
account.php - Shows current session details and allows changing of account password
-->
<?php
session_start();
?>



<html>
	<head>
		<title>Account | Security Suite</title>
		
		<!-- Link to the CSS file that drives the page formatting/style -->
		<link href="jomanji_style.css" type="text/css" rel="stylesheet" />
		
		<!--Script tag containing the JavaScript functions used on this page</script>-->
		<script src="client_functions.js"></script>
		
		<?php 
			include ("jomanjifunctions.php");
			checkActiveSession();
		?>
	</head>
	
	<body onload="displayAlert()">
	
		<div class="container">
		
			<div class="PageHeader">
				
				<p class="HeaderLeft"><a href="index.php"><img id="companyLogo" src="img/logo.png" alt="index.php"></a></p>
					
				<div class="HeaderRight"><a href="logout.php" id="logout">Logout</a></div>
			</div>	
			
			<div class="AccountHeader">

				
				<h1><center><?php echo "Account Details - ".$_SESSION["username"] ?></center></h1>
				<noscript><center>Please enable JavaScript for complete page functionality</center></noscript>
				<br>
				<br>
			</div>

			<div class="AccountContainer">
			
				<h2>Account Information</h2>
				
				<?php fetchAccountDetails(); ?>
			</div>
			
			<div class="AccountContainer">
			
				<h2>Change Password</h2>
				
				<form id='changePassForm' onSubmit="return comparePass()" method="post" action="accountmodify.php">
					<table>
						<tr>
							<th>Current Password</th>
							<td><input type="password" id="currentPassword" name="currentpassword" size="25" required></td>
						</tr>
				
						<tr>
							<th>New Password</th>
							<td><input type="password" id="newPassword" name="newpassword" size="25" required></td>
						</tr>
					
						<tr>
							<th>Confirm New Password</th>
							<td><input type="password" id="confirmPassword" name="confirmpassword" size="25" required></td>
						</tr>							
					</table>
					<input type='hidden' id='scriptCheck' name='scriptCheck' value='N'>
					<button class="CapButton">Change Password</button>
				</form>
			</div>
			
		</div>
		
		<footer>
		
			<script>
				
				//call scriptCheck function to confirm if user has client side scripting enabled
				scriptCheck('scriptCheck');
			</script>
				
			<p class="FooterElements">&#169; Copyright [Placeholder] 2021</p>
			<div class="FooterElements">
				
				<a href="legal.html">Legal Information</a>
				<a href="sitemap.html">Sitemap</a>
			</div>
		</footer>
	</body>
</html>