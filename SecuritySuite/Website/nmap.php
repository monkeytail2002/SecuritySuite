<?php session_start(); ?>
<html>
	<head>
	</head>
	
	<body>
		<div class="container">
			<h1><center>NMap Scan</center></h1>
			<br><br>
			<h2><center>Please enter your search terms.</center></h2>
		</div>
		
		
		<?php
			
			$tool = $_SESSION['tool'];
			$scan = $_SESSION['scan'];
			$scanOption = $_SESSION['scanOption'];
		
		
			if ($scan == "Port"){
				switch($scanOption){
					case "TCP":
						?>
						<center><form action="results.php" method="POST">
							Enter the I.P. range: <input type="text" name="ipRange"><br>
							Enter the port range: <input type="text" name="ports"><br><br>
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 3;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
					case "SCTP";
						echo "Test SCTP";
						$chosenScan = 4;
						break;
					case "Null";
						echo "Test Null";
						$chosenScan = 5;
						break;
					case "Fin";
						echo "Test Fin";
						$chosenScan = 6;
						break;
					case "Xmas";
						echo "Test Xmas";
						$chosenScan = 7;
						break;
					case "TCP/ACK";
						echo "Test TCP/ACK";
						$chosenScan = 8;
						break;
					case "Advanced SCTP";
						echo "Test Advanced SCTP";
						$chosenScan = 9;
						break;
					case "IP";
						echo "Test IP";
						$chosenScan = 10;
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
								<input type = "submit" value="Submit" name="Submit"/>
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
								<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
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
							<input type = "submit" value="Submit" name="Submit"/>
							</form></center>
						<?php
						$chosenScan = 34;
						$_SESSION['chosenScan'] = $chosenScan;
						break;
	
				}
					
			}
		?>
		
	</body>
</html>