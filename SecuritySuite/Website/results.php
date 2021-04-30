<!--
Angus MacDonald, Jordan Laing
15009351, 15009237
27/04/2021
results.php - Display returned tool scan results
(Python tool search, switch case, and databse insert code by Angus, CSS and HTML element code by Jordan)
-->

<?php 
	session_start(); 
	include('DbConnect.php'); 
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
		
		
		<div class="container">
			<h1><center>NMap Scan Results</center></h1>
			<br>
		</div>
		
		<div class="NmapResults">
		<?php
			
			
			$userID = $_SESSION["userID"];
			$ipRange = $_POST['ipRange'];
			$ports = $_POST['ports'];
			$chosenScan = $_SESSION['chosenScan'];

			switch($chosenScan){
					case "1":
					?>	
						<h3><center>TCP Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
					//			echo $python_return;
						$return_object = json_decode($python_return, true);
					//			print_r($return_object);	
					?>
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "TCP Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							

								
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();
							


						
							echo '<br><b>Port Information</b>:<br>';
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								echo '<br>';
								
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));

						
							}

							
						}
		
			
							
					
						break;
					case "2":
	?>	
						<h3><center>Stealth Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//								echo $python_return;
						$return_object = json_decode($python_return, true);
					//			print_r($return_object);	
					?>
						<b>State Information</b>:
				<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "TCP/SYN Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];					
					

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
							
								
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();
							
							echo '<br><b>Port Information</b>:<br>';		
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<br>';
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));								
								
								
								
							}
						}
						break;
					case "3":
					?>	
						<h3><center>UDP Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "UDP Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];		

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: udp</p>';
							echo '<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
								
								
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();
							
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
							$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, scanTime) VALUES(?,?,?,?,?,CURRENT_TIME())");
							$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id));
							$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
							$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
							$link_stmt->execute(array($userID,$scan_id));				
							
						}
						break;
					case "4":
					?>
						<h3><center>SCTP Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "SCTP Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<br><b>Addresses</b>:';
							echo '<p class="NmapList">ipv4: '.$i['address']['ipv4'].'</p>';
							echo '<p class="NmapList">ipv6: '.$i['address']['ipv6'].'</p>';
							echo '<p class="NmapList">mac: '.$i['address']['mac'].'</p>';
							echo '<br>';
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$hostip4Address = $i['address']['ipv4'];
							$hostip6Address  =$i['address']['ipv6'];
							$hostMacAddress = $i['address']['mac'];
							$protocol = $i['protocollist'][0]['protocols'];
								
								
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason,hostip4Address,hostip6Address,hostmacAddress) VALUES(?,?,?,?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason,$hostip4Address,$hostip6Address,$hostMacAddress));
							$host_id = $db->lastInsertId();
							
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
							$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, scanTime) VALUES(?,?,?,?,?,CURRENT_TIME())");
							$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id));
							$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
							$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
							$link_stmt->execute(array($userID,$scan_id));				
							
							
						}
						break;
					case "5":
					?>	
						<h3><center>Null Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
					//			echo $python_return;
						$return_object = json_decode($python_return, true);
//								print_r($return_object);	
					?>
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Null Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							

								
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();
							


						
							echo '<br><b>Port Information</b>:<br>';
							if($i['protocollist'][0]['portlist']){
								foreach($i['protocollist'][0]['portlist'] as $port => $j){
									echo '<p class="NmapList">Port: '.$j['port'].'</p>';
									echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
									echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
									echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
									$port = $j['port'];
									$portName = $j['portname'];
									$portState = $j['portstate'];
									$portReason = $j['portreason'];
									echo '<br>';
									
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason));
									$port_id = $db->lastInsertId();
				
				//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));
								}
							} else {
								echo "No results returned.<br><br>";
								//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID,scanTime) VALUES(?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));
							}
						}
						
							

							

					
						break;
					case "6":
					?>
						<h3><center>Fin Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);
				?>
						
						<b>State Information</b>:
				<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Fin Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();							
							
							
							if($i['protocollist'][0]['portlist']){
								foreach($i['protocollist'][0]['portlist'] as $port => $j){
									echo '<p class="NmapList">Port: '.$j['port'].'</p>';
									echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
									echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
									echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
									$port = $j['port'];
									$portName = $j['portname'];
									$portState = $j['portstate'];
									$portReason = $j['portreason'];
									echo '<br>';
									
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason));
									$port_id = $db->lastInsertId();
				
				//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));
								}
							} else {
								echo "No results returned.<br><br>";
								//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID,scanTime) VALUES(?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));
							}
						}
						
						break;
					case "7":
					?>
						<h3><center>Xmas Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);
			?>
						
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Xmas Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();										
							
							
							if($i['protocollist'][0]['portlist']){
								foreach($i['protocollist'][0]['portlist'] as $port => $j){
									echo '<p class="NmapList">Port: '.$j['port'].'</p>';
									echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
									echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
									echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
									$port = $j['port'];
									$portName = $j['portname'];
									$portState = $j['portstate'];
									$portReason = $j['portreason'];
									echo '<br>';
									
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason));
									$port_id = $db->lastInsertId();
				
				//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));
								}
							} else {
								echo "No results returned.<br><br>";
								//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID,scanTime) VALUES(?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));
							}
						}
						break;
					case "8":
					?>
						<h3><center>TCP/ACK Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);
//					?>
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "TCP/ACK Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();		
							
							if($i['protocollist'][0]['portlist']){
								foreach($i['protocollist'][0]['portlist'] as $port => $j){
									echo '<p class="NmapList">Port: '.$j['port'].'</p>';
									echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
									echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
									echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
									$port = $j['port'];
									$portName = $j['portname'];
									$portState = $j['portstate'];
									$portReason = $j['portreason'];
									echo '<br>';
									
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason));
									$port_id = $db->lastInsertId();
				
				//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));
								}
							} else {
								echo "No results returned.<br><br>";
								//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID,scanTime) VALUES(?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));
							}
						}
						break;
					case "9":
					?>
						<h3><center>Cookie Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
//					?>
						
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Cookie Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<br><b>Addresses</b>:';
							echo '<p class="NmapList">ipv4: '.$i['address']['ipv4'].'</p>';
							echo '<p class="NmapList">ipv6: '.$i['address']['ipv6'].'</p>';
							echo '<p class="NmapList">mac: '.$i['address']['mac'].'</p>';
							echo '<br>';
							
							
							//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason,hostip4Address,hostip6Address,hostmacAddress) VALUES(?,?,?,?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason,$hostip4Address,$hostip6Address,$hostMacAddress));
							$host_id = $db->lastInsertId();
							
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
							$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, scanTime) VALUES(?,?,?,?,?,CURRENT_TIME())");
							$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id));
							$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
							$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
							$link_stmt->execute(array($userID,$scan_id));
						}
						break;
					case "10":
					?>	
						<h3><center>IP Protocol Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//					//			echo $python_return;
						$return_object = json_decode($python_return, true);
//					//			print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "IP Protocol Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];					

					//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));
							}
						}
						break;
					case "11":
					?>	
						<h3><center>Banner Grab</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Banner Grab";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];	
					
//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();		
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';							
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));								
							}
						}
						break;
					case "12":
					?>	
						<h3><center>Vulnerability Scan</center></h3>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Vulnerability Scan";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];	

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<p class="NmapList">Vulnerabilities Found: <br>'.$j['script']['vulners'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
								$portVuln = $j['script']['vulners'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE, scriptOne) VALUES(?,?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE,$portVuln));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}
						break;
					case "13":

					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 0</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 0";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];
//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();		
							
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));		
							}
						}

						break;
					
					case "14":
					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 1</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 1";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];


//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "15":
					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 2</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 2";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "16":
					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 3</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 3";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "17":
					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 4</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 4";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "18":
					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 5</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 5";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "19":
					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 6</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 6";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "20":
					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 7</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 7";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "21":
					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 8</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 8";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "22":
					?>	
						<h3><center> Version Detection Scan</center></h3>
						<h4><center>Intensity Level 9</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
		
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Version Detection - Level 9";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];


//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "23":
					?>	
						<h3><center> OS Detection Scan</center></h3>
						<h4><center>Limited Scan</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "OS Detection - Limited";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Uptime (s): '.$i['uptime'].'</p>';
							echo '<p class="NmapList">Last reboot:: '.$i['lastboot'].'</p>';						
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>OS Information</b>:<br>';
							echo '<p class="NmapList">Detected OS: '.$i['oslist'][0]['name'].'</p>';
							echo '<p class="NmapList">Accuracy of Detection(%): '.$i['oslist'][0]['accuracy'].'%</p>';
							echo '<p class="NmapList">Type of OS: '.$i['oslist'][0]['matchlist'][0]['type'].'</p>';
							echo '<p class="NmapList">OS Vendor: '.$i['oslist'][0]['matchlist'][0]['vendor'].'</p>';
							echo '<p class="NmapList">Kernel: '.$i['oslist'][0]['matchlist'][0]['osfamily'].' '.$i['oslist'][0]['matchlist'][0]['osgen'].'</p>';
							echo '<p class="NmapList">OS Match accuracy(%): '.$i['oslist'][0]['matchlist'][0]['matchaccuracy'].'%</p>';
							echo '<p class="NmapList">Common Platform Enumeration: '.$i['oslist'][0]['matchlist'][0]['cpe'][0].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							$osname = $i['oslist'][0]['name'];
							$osaccuracy = $i['oslist'][0]['accuracy'];
							$ostype = $i['oslist'][0]['matchlist'][0]['type'];
							$osvendor = $i['oslist'][0]['matchlist'][0]['vendor'];
							$osfamily = $i['oslist'][0]['matchlist'][0]['osfamily'];
							$osgen = $i['oslist'][0]['matchlist'][0]['osgen'];
							$matchaccuracy = $i['oslist'][0]['matchlist'][0]['matchaccuracy'];
							$oscpe = $i['oslist'][0]['matchlist'][0]['cpe'][0];
							
//							Insert into the os table.
							$os_stmt = $db->prepare("INSERT INTO os(osName, osAccuracy, osType, osVendor, osfamily, osGen, matchAccuracy, osCPE) VALUES(?,?,?,?,?,?,?,?)");
							$os_stmt->execute(array($osname,$osaccuracy,$ostype,$osvendor,$osfamily,$osgen,$matchaccuracy,$oscpe));
							$os_id = $db->lastInsertId();	
							
//							Insert into the host table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();								
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, osID,protocolID,scanTime) VALUES(?,?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$os_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "24":
					?>	
						<h3><center> OS Detection Scan</center></h3>
						<h4><center>Guess Scan</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "OS Detection - Guess";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Uptime (s): '.$i['uptime'].'</p>';
							echo '<p class="NmapList">Last reboot:: '.$i['lastboot'].'</p>';							
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>OS Information</b>:<br>';
							echo '<p class="NmapList">Detected OS: '.$i['oslist'][0]['name'].'</p>';
							echo '<p class="NmapList">Accuracy of Detection(%): '.$i['oslist'][0]['accuracy'].'%</p>';
							echo '<p class="NmapList">Type of OS: '.$i['oslist'][0]['matchlist'][0]['type'].'</p>';
							echo '<p class="NmapList">OS Vendor: '.$i['oslist'][0]['matchlist'][0]['vendor'].'</p>';
							echo '<p class="NmapList">Kernel: '.$i['oslist'][0]['matchlist'][0]['osfamily'].' '.$i['oslist'][0]['matchlist'][0]['osgen'].'</p>';
							echo '<p class="NmapList">OS Match accuracy(%): '.$i['oslist'][0]['matchlist'][0]['matchaccuracy'].'%</p>';
							echo '<p class="NmapList">Common Platform Enumeration: '.$i['oslist'][0]['matchlist'][0]['cpe'][0].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							$osname = $i['oslist'][0]['name'];
							$osaccuracy = $i['oslist'][0]['accuracy'];
							$ostype = $i['oslist'][0]['matchlist'][0]['type'];
							$osvendor = $i['oslist'][0]['matchlist'][0]['vendor'];
							$osfamily = $i['oslist'][0]['matchlist'][0]['osfamily'];
							$osgen = $i['oslist'][0]['matchlist'][0]['osgen'];
							$matchaccuracy = $i['oslist'][0]['matchlist'][0]['matchaccuracy'];
							$oscpe = $i['oslist'][0]['matchlist'][0]['cpe'][0];
							
//							Insert into the os table.
							$os_stmt = $db->prepare("INSERT INTO os(osName, osAccuracy, osType, osVendor, osfamily, osGen, matchAccuracy, osCPE) VALUES(?,?,?,?,?,?,?,?)");
							$os_stmt->execute(array($osname,$osaccuracy,$ostype,$osvendor,$osfamily,$osgen,$matchaccuracy,$oscpe));
							$os_id = $db->lastInsertId();	
							
//							Insert into the host table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, osID,protocolID,scanTime) VALUES(?,?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$os_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
						}

						break;
					case "25":
					?>	
						<h3><center> OS Detection Scan</center></h3>
						<h4><center>Maximum Attempts Tried- 1</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "OS Detection - Max Attempts 1";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Uptime (s): '.$i['uptime'].'</p>';
							echo '<p class="NmapList">Last reboot:: '.$i['lastboot'].'</p>';							
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>OS Information</b>:<br>';
							echo '<p class="NmapList">Detected OS: '.$i['oslist'][0]['name'].'</p>';
							echo '<p class="NmapList">Accuracy of Detection(%): '.$i['oslist'][0]['accuracy'].'%</p>';
							echo '<p class="NmapList">Type of OS: '.$i['oslist'][0]['matchlist'][0]['type'].'</p>';
							echo '<p class="NmapList">OS Vendor: '.$i['oslist'][0]['matchlist'][0]['vendor'].'</p>';
							echo '<p class="NmapList">Kernel: '.$i['oslist'][0]['matchlist'][0]['osfamily'].' '.$i['oslist'][0]['matchlist'][0]['osgen'].'</p>';
							echo '<p class="NmapList">OS Match accuracy(%): '.$i['oslist'][0]['matchlist'][0]['matchaccuracy'].'%</p>';
							echo '<p class="NmapList">Common Platform Enumeration: '.$i['oslist'][0]['matchlist'][0]['cpe'][0].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							$osname = $i['oslist'][0]['name'];
							$osaccuracy = $i['oslist'][0]['accuracy'];
							$ostype = $i['oslist'][0]['matchlist'][0]['type'];
							$osvendor = $i['oslist'][0]['matchlist'][0]['vendor'];
							$osfamily = $i['oslist'][0]['matchlist'][0]['osfamily'];
							$osgen = $i['oslist'][0]['matchlist'][0]['osgen'];
							$matchaccuracy = $i['oslist'][0]['matchlist'][0]['matchaccuracy'];
							$oscpe = $i['oslist'][0]['matchlist'][0]['cpe'][0];
							
//							Insert into the os table.
							$os_stmt = $db->prepare("INSERT INTO os(osName, osAccuracy, osType, osVendor, osfamily, osGen, matchAccuracy, osCPE) VALUES(?,?,?,?,?,?,?,?)");
							$os_stmt->execute(array($osname,$osaccuracy,$ostype,$osvendor,$osfamily,$osgen,$matchaccuracy,$oscpe));
							$os_id = $db->lastInsertId();	
							
//							Insert into the host table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, osID,protocolID,scanTime) VALUES(?,?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$os_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));	
							}
							
						}

						break;
					case "26":
					?>	
						<h3><center> OS Detection Scan</center></h3>
						<h4><center>Maximum Attempts Tried- 2</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "OS Detection - Max Attempts 2";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Uptime (s): '.$i['uptime'].'</p>';
							echo '<p class="NmapList">Last reboot:: '.$i['lastboot'].'</p>';							
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>OS Information</b>:<br>';
							echo '<p class="NmapList">Detected OS: '.$i['oslist'][0]['name'].'</p>';
							echo '<p class="NmapList">Accuracy of Detection(%): '.$i['oslist'][0]['accuracy'].'%</p>';
							echo '<p class="NmapList">Type of OS: '.$i['oslist'][0]['matchlist'][0]['type'].'</p>';
							echo '<p class="NmapList">OS Vendor: '.$i['oslist'][0]['matchlist'][0]['vendor'].'</p>';
							echo '<p class="NmapList">Kernel: '.$i['oslist'][0]['matchlist'][0]['osfamily'].' '.$i['oslist'][0]['matchlist'][0]['osgen'].'</p>';
							echo '<p class="NmapList">OS Match accuracy(%): '.$i['oslist'][0]['matchlist'][0]['matchaccuracy'].'%</p>';
							echo '<p class="NmapList">Common Platform Enumeration: '.$i['oslist'][0]['matchlist'][0]['cpe'][0].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							$osname = $i['oslist'][0]['name'];
							$osaccuracy = $i['oslist'][0]['accuracy'];
							$ostype = $i['oslist'][0]['matchlist'][0]['type'];
							$osvendor = $i['oslist'][0]['matchlist'][0]['vendor'];
							$osfamily = $i['oslist'][0]['matchlist'][0]['osfamily'];
							$osgen = $i['oslist'][0]['matchlist'][0]['osgen'];
							$matchaccuracy = $i['oslist'][0]['matchlist'][0]['matchaccuracy'];
							$oscpe = $i['oslist'][0]['matchlist'][0]['cpe'][0];
							
//							Insert into the os table.
							$os_stmt = $db->prepare("INSERT INTO os(osName, osAccuracy, osType, osVendor, osfamily, osGen, matchAccuracy, osCPE) VALUES(?,?,?,?,?,?,?,?)");
							$os_stmt->execute(array($osname,$osaccuracy,$ostype,$osvendor,$osfamily,$osgen,$matchaccuracy,$oscpe));
							$os_id = $db->lastInsertId();	
							
//							Insert into the host table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, osID,protocolID,scanTime) VALUES(?,?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$os_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));
							}
						}

						break;
					case "27":
					?>	
						<h3><center> OS Detection Scan</center></h3>
						<h4><center>Maximum Attempts Tried- 3</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "OS Detection - Max Attempts 3";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Uptime (s): '.$i['uptime'].'</p>';
							echo '<p class="NmapList">Last reboot:: '.$i['lastboot'].'</p>';							
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>OS Information</b>:<br>';
							echo '<p class="NmapList">Detected OS: '.$i['oslist'][0]['name'].'</p>';
							echo '<p class="NmapList">Accuracy of Detection(%): '.$i['oslist'][0]['accuracy'].'%</p>';
							echo '<p class="NmapList">Type of OS: '.$i['oslist'][0]['matchlist'][0]['type'].'</p>';
							echo '<p class="NmapList">OS Vendor: '.$i['oslist'][0]['matchlist'][0]['vendor'].'</p>';
							echo '<p class="NmapList">Kernel: '.$i['oslist'][0]['matchlist'][0]['osfamily'].' '.$i['oslist'][0]['matchlist'][0]['osgen'].'</p>';
							echo '<p class="NmapList">OS Match accuracy(%): '.$i['oslist'][0]['matchlist'][0]['matchaccuracy'].'%</p>';
							echo '<p class="NmapList">Common Platform Enumeration: '.$i['oslist'][0]['matchlist'][0]['cpe'][0].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							$osname = $i['oslist'][0]['name'];
							$osaccuracy = $i['oslist'][0]['accuracy'];
							$ostype = $i['oslist'][0]['matchlist'][0]['type'];
							$osvendor = $i['oslist'][0]['matchlist'][0]['vendor'];
							$osfamily = $i['oslist'][0]['matchlist'][0]['osfamily'];
							$osgen = $i['oslist'][0]['matchlist'][0]['osgen'];
							$matchaccuracy = $i['oslist'][0]['matchlist'][0]['matchaccuracy'];
							$oscpe = $i['oslist'][0]['matchlist'][0]['cpe'][0];
							
//							Insert into the os table.
							$os_stmt = $db->prepare("INSERT INTO os(osName, osAccuracy, osType, osVendor, osfamily, osGen, matchAccuracy, osCPE) VALUES(?,?,?,?,?,?,?,?)");
							$os_stmt->execute(array($osname,$osaccuracy,$ostype,$osvendor,$osfamily,$osgen,$matchaccuracy,$oscpe));
							$os_id = $db->lastInsertId();	
							
//							Insert into the host table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, osID,protocolID,scanTime) VALUES(?,?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$os_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));
							}
						}

						break;
					case "28":
					?>	
						<h3><center> OS Detection Scan</center></h3>
						<h4><center>Maximum Attempts Tried- 4</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "OS Detection - Max Attempts 4";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Uptime (s): '.$i['uptime'].'</p>';
							echo '<p class="NmapList">Last reboot:: '.$i['lastboot'].'</p>';							
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>OS Information</b>:<br>';
							echo '<p class="NmapList">Detected OS: '.$i['oslist'][0]['name'].'</p>';
							echo '<p class="NmapList">Accuracy of Detection(%): '.$i['oslist'][0]['accuracy'].'%</p>';
							echo '<p class="NmapList">Type of OS: '.$i['oslist'][0]['matchlist'][0]['type'].'</p>';
							echo '<p class="NmapList">OS Vendor: '.$i['oslist'][0]['matchlist'][0]['vendor'].'</p>';
							echo '<p class="NmapList">Kernel: '.$i['oslist'][0]['matchlist'][0]['osfamily'].' '.$i['oslist'][0]['matchlist'][0]['osgen'].'</p>';
							echo '<p class="NmapList">OS Match accuracy(%): '.$i['oslist'][0]['matchlist'][0]['matchaccuracy'].'%</p>';
							echo '<p class="NmapList">Common Platform Enumeration: '.$i['oslist'][0]['matchlist'][0]['cpe'][0].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							$osname = $i['oslist'][0]['name'];
							$osaccuracy = $i['oslist'][0]['accuracy'];
							$ostype = $i['oslist'][0]['matchlist'][0]['type'];
							$osvendor = $i['oslist'][0]['matchlist'][0]['vendor'];
							$osfamily = $i['oslist'][0]['matchlist'][0]['osfamily'];
							$osgen = $i['oslist'][0]['matchlist'][0]['osgen'];
							$matchaccuracy = $i['oslist'][0]['matchlist'][0]['matchaccuracy'];
							$oscpe = $i['oslist'][0]['matchlist'][0]['cpe'][0];
							
//							Insert into the os table.
							$os_stmt = $db->prepare("INSERT INTO os(osName, osAccuracy, osType, osVendor, osfamily, osGen, matchAccuracy, osCPE) VALUES(?,?,?,?,?,?,?,?)");
							$os_stmt->execute(array($osname,$osaccuracy,$ostype,$osvendor,$osfamily,$osgen,$matchaccuracy,$oscpe));
							$os_id = $db->lastInsertId();	
							
//							Insert into the host table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, osID,protocolID,scanTime) VALUES(?,?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$os_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));
							}
						}

						break;
					case "29":
					?>	
						<h3><center> OS Detection Scan</center></h3>
						<h4><center>Maximum Attempts Tried- 5</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "OS Detection - Max Attempts 5";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Uptime (s): '.$i['uptime'].'</p>';
							echo '<p class="NmapList">Last reboot:: '.$i['lastboot'].'</p>';							
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>OS Information</b>:<br>';
							echo '<p class="NmapList">Detected OS: '.$i['oslist'][0]['name'].'</p>';
							echo '<p class="NmapList">Accuracy of Detection(%): '.$i['oslist'][0]['accuracy'].'%</p>';
							echo '<p class="NmapList">Type of OS: '.$i['oslist'][0]['matchlist'][0]['type'].'</p>';
							echo '<p class="NmapList">OS Vendor: '.$i['oslist'][0]['matchlist'][0]['vendor'].'</p>';
							echo '<p class="NmapList">Kernel: '.$i['oslist'][0]['matchlist'][0]['osfamily'].' '.$i['oslist'][0]['matchlist'][0]['osgen'].'</p>';
							echo '<p class="NmapList">OS Match accuracy(%): '.$i['oslist'][0]['matchlist'][0]['matchaccuracy'].'%</p>';
							echo '<p class="NmapList">Common Platform Enumeration: '.$i['oslist'][0]['matchlist'][0]['cpe'][0].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							$osname = $i['oslist'][0]['name'];
							$osaccuracy = $i['oslist'][0]['accuracy'];
							$ostype = $i['oslist'][0]['matchlist'][0]['type'];
							$osvendor = $i['oslist'][0]['matchlist'][0]['vendor'];
							$osfamily = $i['oslist'][0]['matchlist'][0]['osfamily'];
							$osgen = $i['oslist'][0]['matchlist'][0]['osgen'];
							$matchaccuracy = $i['oslist'][0]['matchlist'][0]['matchaccuracy'];
							$oscpe = $i['oslist'][0]['matchlist'][0]['cpe'][0];
							
//							Insert into the os table.
							$os_stmt = $db->prepare("INSERT INTO os(osName, osAccuracy, osType, osVendor, osfamily, osGen, matchAccuracy, osCPE) VALUES(?,?,?,?,?,?,?,?)");
							$os_stmt->execute(array($osname,$osaccuracy,$ostype,$osvendor,$osfamily,$osgen,$matchaccuracy,$oscpe));
							$os_id = $db->lastInsertId();	
							
//							Insert into the host table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<br>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
																
//								Insert into the port table
								$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
								$port_stmt->execute(array($port,$portName,$portState,$portReason));
								$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
								$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
								$protocol_stmt->execute(array($protocol, $port_id));
								$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
								$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, osID,protocolID,scanTime) VALUES(?,?,?,?,?,?,?,CURRENT_TIME())");
								$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$os_id,$protocol_id));
								$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
								$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
								$link_stmt->execute(array($userID,$scan_id));
							}
						}

						break;
					case "30":
					?>	
						<h3><center>NSE Scripts</center></h3>
						<h4><center>HTTP Auth Finder Script</center></h4>
					<?php

						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "HTTP Auth Finder";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<p class="NmapList">Results:'.'</p>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
								
								if ($j['noscript']){
									echo '<p class="PortList">'.$j['noscript'].'</p>';
																
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
									$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));	
			
								} else {
									if ($j['script']['http-auth-finder']){
										echo '<p class="PortList">Authentication Found: '.$j['script']['http-auth-finder'].'</p></br>';
										echo '<p class="PortList">Server Header: '.$j['script']['http-server-header'].'</p>';
										$portScriptone = $j['script']['http-auth-finder'];
										$portScripttwo = $j['script']['http-server-header'];
										//								Insert into the port table
										$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE,scriptOne, scriptTwo) VALUES(?,?,?,?,?,?,?,?,?,?)");
										$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE,$portScriptone, $portScripttwo));
										$port_id = $db->lastInsertId();
										
										//								Insert into protocol table
										$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
										$protocol_stmt->execute(array($protocol, $port_id));
										$protocol_id = $db->lastInsertId();
										
										//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information 										overwriting data.
										$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
										$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
										$scan_id = $db->lastInsertId();
										
										//								Insert scan and user id into linking table
										$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
										$link_stmt->execute(array($userID,$scan_id));
										} else{
											echo "No Authentication found.";
											echo '<p class="PortList">Server Header: '.$j['script']['http-server-header'].'</p>';
											$portScripttwo = $j['script']['http-server-header'];
											
											$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE,scriptTwo) VALUES(?,?,?,?,?,?,?,?,?)");
											$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE,$portScripttwo));
											$port_id = $db->lastInsertId();
											//								Insert into protocol table
											$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
											$protocol_stmt->execute(array($protocol, $port_id));
											$protocol_id = $db->lastInsertId();
											
										//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information 										overwriting data.
											$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
											$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
											$scan_id = $db->lastInsertId();
											
										//								Insert scan and user id into linking table
											$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
											$link_stmt->execute(array($userID,$scan_id));
										}
								}
								echo '<br>';	
							}
						}


						break;
					case "31":
					?>	
						<h3><center>NSE Scripts</center></h3>
						<h4><center>HTTP Auth Script</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "HTTP Auth Script";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();	
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<p class="NmapList">Results:'.'</p>';
								
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
								
								if ($j['noscript']){
									echo '<p class="PortList">'.$j['noscript'].'</p>';
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
									$port_id = $db->lastInsertId();
								
	//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));				
								} else {
									echo '<p class="PortList">Authentication: '.$j['script']['http-auth'].'</p>';
									echo '<p class="PortList">Server Header: '.$j['script']['http-server-header'].'</p>';
									$portAuth = $j['script']['http-auth'];
									$portHeader = $j['script']['http-server-header'];
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE, scriptOne, scriptTwo) VALUES(?,?,?,?,?,?,?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE,$portAuth, $portHeader));
									$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));	
								}
								echo '<br>';
							}
						}

						break;
					case "32":
					?>	
						<h3><center>NSE Scripts</center></h3>
						<h4><center>HTTP Enum Script</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "HTTP Enum Script";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];
			

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<p class="NmapList">Results:'.'</p>';
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
								
								if ($j['noscript']){
									echo '<p class="PortList">'.$j['noscript'].'</p>';
									
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
									$port_id = $db->lastInsertId();
								
	//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));
			
								} else {
									echo '<p class="PortList">Enumeration: '.$j['script']['http-enum'].'</p>';
									
									$portScript = $j['script']['http-enum'];
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE,scriptOne) VALUES(?,?,?,?,?,?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE,$portScript));
									$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));	
								}
								echo '<br>';
							}
						}

						break;
					case "33":
				?>	
						<h3><center>NSE Scripts</center></h3>
						<h4><center>HTTP Methods Script</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "HTTP Methods Script";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];

//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';	
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Product: '.$j['product'].'</p>';
								echo '<p class="NmapList">Version: '.$j['version'].'</p>';
								echo '<p class="NmapList">Extra Information: '.$j['extrainfo'].'</p>';
								echo '<p class="NmapList">Common Platform Enumeration: '.$j['cpe'].'</p>';
								echo '<p class="NmapList">Results:'.'</p>';
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								$portProduct = $j['product'];
								$portVersion = $j['version'];
								$portExtraInformation = $j['extrainfo'];
								$portCPE = $j['cpe'];
							
								if ($j['noscript']){
									echo '<p class="PortList">'.$j['noscript'].'</p>';
			
									//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE) VALUES(?,?,?,?,?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE));
									$port_id = $db->lastInsertId();
								
	//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));
								} else {
									echo '<p class="PortList">Methods: '.$j['script']['http-methods'].'</p>';
									
									$portScript = $j['script']['http-methods'];
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,product, version, extrainfo, portCPE,scriptOne) VALUES(?,?,?,?,?,?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason,$portProduct,$portVersion,$portExtraInformation,$portCPE,$portScript));
									$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));	
								}
								echo '<br>';
							}
						}

						break;
					case "34":
					?>	
						<h3><center>NSE Scripts</center></h3>
						<h4><center>Sitemap Generator Script</center></h4>
					<?php
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/jobs.sh $ipRange~$ports~$chosenScan");
//						echo $python_return;
						$return_object = json_decode($python_return, true);
//						print_r($return_object);	
					?>
					
						<b>State Information</b>:
					<?php
						echo "<p class='NmapList'>Up: ".$return_object[0]['uphosts']."</p>";
						echo "<p class='NmapList'>Down: ".$return_object[0]['downhosts']."</p>";
						echo "<p class='NmapList'>Total Hosts: ".$return_object[0]['totalhosts']."</p>";
						$scanType = "Sitemap Generator Script";
						$scanUp = $return_object[0]['uphosts'];
						$scanDown = $return_object[0]['downhosts'];
						$scanTotal = $return_object[0]['totalhosts'];


//			Put nested arrays into variables that can be worked on
						$hosts_information = $return_object[0]['hosts'];
		//			Iterate through nested host array
						foreach($hosts_information as $host => $i){
							echo '<br><br><b>Host Scanned</b>:<br>';
							echo '<p class="NmapList">Host IP: '.$i['host'].'</p>';
							echo '<p class="NmapList">Hostname: '.$i['hostname'].'</p>';
							echo '<p class="NmapList">State of Host: '.$i['state'].'</p>';
							echo '<p class="NmapList">Host Reason: '.$i['hostreason'].'</p>';
							echo '<p class="NmapList">Protocol Scanned: '.$i['protocollist'][0]['protocols'].'</p>';
							echo '<br><b>Port Information</b>:<br>';
							$hostName = $i['hostname'];
							$ipScanned = $i['host'];
							$hostState = $i['state'];
							$hostReason = $i['hostreason'];
							$protocol = $i['protocollist'][0]['protocols'];
							
//							Insert into the hosts table.
							$host_stmt = $db->prepare("INSERT INTO hosts(hostName, ipScanned, hostState,hostReason) VALUES(?,?,?,?)");
							$host_stmt->execute(array($hostName,$ipScanned,$hostState,$hostReason));
							$host_id = $db->lastInsertId();							
							
							foreach($i['protocollist'][0]['portlist'] as $port => $j){
								echo '<p class="NmapList">Port: '.$j['port'].'</p>';
								echo '<p class="NmapList">Port Name: '.$j['portname'].'</p>';
								echo '<p class="NmapList">Port State: '.$j['portstate'].'</p>';
								echo '<p class="NmapList">Reason: '.$j['portreason'].'</p>';
								echo '<p class="NmapList">Results:'.'</p>';
								$port = $j['port'];
								$portName = $j['portname'];
								$portState = $j['portstate'];
								$portReason = $j['portreason'];
								if ($j['noscript']){
									echo '<p class="PortList">'.$j['noscript'].'</p>';
							//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason) VALUES(?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason));
									$port_id = $db->lastInsertId();
								
	//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));
			
								} else {
									echo '<p class="PortList">Sitemap: '.$j['script']['http-sitemap-generator'].'</p>';
									$portScript = $j['script']['http-sitemap-generator'];
//								Insert into the port table
									$port_stmt = $db->prepare("INSERT INTO port(port,portName,portState,portReason,scriptOne) VALUES(?,?,?,?,?)");
									$port_stmt->execute(array($port,$portName,$portState,$portReason, $portScript));
									$port_id = $db->lastInsertId();
								
				//								Insert into protocol table
									$protocol_stmt = $db->prepare("INSERT INTO protocol(protocol, portID) VALUES(?,?)");
									$protocol_stmt->execute(array($protocol, $port_id));
									$protocol_id = $db->lastInsertId();
								
//							Insert into the scan table.  This creates a new scan entry for each host to avoid host information overwriting data.
									$scan_stmt = $db->prepare("INSERT INTO scan(scanType, scanUp, scanDown, scanTotal, hostID, protocolID,scanTime) VALUES(?,?,?,?,?,?,CURRENT_TIME())");
									$scan_stmt->execute(array($scanType,$scanUp,$scanDown,$scanTotal,$host_id,$protocol_id));
									$scan_id = $db->lastInsertId();
								
//								Insert scan and user id into linking table
									$link_stmt = $db->prepare("INSERT INTO userScan(userID, scanID) VALUES(?,?)");
									$link_stmt->execute(array($userID,$scan_id));
								}
								echo '<br>';
							}
						}
						break;
			}
		?>
		</div>
	</body>
</html>