<!--
Angus MacDonald, Jordan Laing
15009351, 15009237
22/03/2021
nmap.php - Loads required input parameters for users selected nmap scan.
(Switch case by Angus, CSS and HTML element code by Jordan)
-->

<?php 
	session_start(); 
?>

<html>
	<head>
	
		<!-- Link to the CSS file that drives the page formatting/style -->
		<link href="jomanji_style.css" type="text/css" rel="stylesheet" />
		
		<?php 
			include ("jomanjifunctions.php");
			checkActiveSession();
		?>
	</head>
	
	<body>
	
		<div class="PageHeader">
			
			<p class="HeaderLeft"><a href="index.php"><img id="companyLogo" src="img/logo.png" alt="index.php"></a></p>
			
			<div class="HeaderRight"><a href="account.php"><figure><img id="accountLogo"src="img/account.png" alt="account.php"><figcaption>My Account</figcaption></figure></a></div>
		</div>	
			
		<h1><center>NMap Scan</center></h1>
		<br>
		<br>
		
		<div class="container" id="nmapRange">
		
			<h2><center>Please enter your search terms.</center></h2>

		<?php
		
			$scan = $_POST['scan'];
			$scanOption = $_POST['options'];
		
			$_SESSION['scan'] = $scan;
			$_SESSION['scanOption'] = $scanOption;
			
			$tool = $_SESSION['tool'];
		
		
			if ($scan == "Port"){
				switch($scanOption){
					case "TCP":
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 1;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "TCP Syn";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 2;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "UDP";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 3;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "SCTP";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 4;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Null";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 5;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Fin";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 6;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Xmas";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 7;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "TCP/ACK";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 8;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Advanced SCTP";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br>
							Port Range for this scan maxes out at port 255.<br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 9;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "IP";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 10;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
						
				}
				
			} elseif ($scan == "Banner Grab"){
				switch($scanOption){
						case "Banner Grab":
						
				?>
						<center>
							<form action="results.php" method="POST">
								Enter the I.P. range: <input type="text" name="ipRange"><br>
								Enter the port range: <input type="text" name="ports"><br><br>
								<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form>
						</center>
						<?php
						$chosenScan = 11;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Vulnerabilty Scan";
						?>
						<center>
							<form action="results.php" method="POST">
								Enter the I.P. range: <input type="text" name="ipRange"><br>
								Enter the port range: <input type="text" name="ports"><br><br>
								<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form>
						</center>
						<?php
						$chosenScan = 12;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
							
				}
			}
		elseif ($scan == "Version Detection"){
				switch($scanOption){
					case "Version detection - Intensity 0":
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 13;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Version detection - Intensity 1";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 14;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Version detection - Intensity 2";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 15;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Version detection - Intensity 3";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 16;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Version detection - Intensity 4";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 17;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Version detection - Intensity 5";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 18;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Version detection - Intensity 6";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 19;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Version detection - Intensity 7";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 20;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Version detection - Intensity 8";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 21;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Version detection - Intensity 9";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 22;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
						
				}
					
			}  elseif ($scan == "Operating System"){
				switch($scanOption){
					case "Limited":
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 23;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Guess";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 24;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Max tries - 1";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 25;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Max tries - 2";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 26;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Max tries - 3";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 27;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Max tries - 4";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 28;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "Max tries - 5";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 29;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					
				}
					
			}
				elseif ($scan == "NSE Scripts"){
				switch($scanOption){
					case "http-auth-finder":
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 30;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "http-auth";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 31;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "http-enum";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 32;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "http-methods";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 33;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "http-sitemap-generator";
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input class="CapButton" type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 34;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
				}
			}
		?>
		</div>
		
		<footer>
		
			<p class="FooterElements">&#169; Copyright [Placeholder] 2021</p>
				<div class="FooterElements">
				
					<a href="legal.html">Legal Information</a>
					<a href="sitemap.html">Sitemap</a>
				</div>
		</footer>
	</body>
</html>