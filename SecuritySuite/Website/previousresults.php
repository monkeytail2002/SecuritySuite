<!--
Angus MacDonald, Jordan Laing
15009351, 15009237
27/04/2021
previousresults.php - Load scan results archived in the site database
(Database lookup and fetch code by Angus, CSS and HTML element code by Jordan)
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
			
				$scanID = $_GET['q'];

				$host_stmt = $db->query("SELECT * FROM scan JOIN hosts ON scan.hostID = hosts.hostID JOIN protocol ON scan.protocolID = protocol.protocolID JOIN port ON protocol.portID = port.portID WHERE scan.scanID = $scanID")->fetchAll();
			
				$user_stmt = $db->query("SELECT * FROM userScan JOIN scan ON userScan.scanID = scan.scanID JOIN users ON userScan.userID = users.userID WHERE userScan.scanID = $scanID")->fetchAll();
			
				$os_stmt = $db->query("SELECT * FROM os JOIN scan ON os.osID = scan.osID WHERE scan.scanID = $scanID")->fetchAll();
					
				foreach ($user_stmt as $row){
		
					$username = $row[userName];
				}
			
				foreach($os_stmt as $row){
			
					$osName = $row[osName];
					$osAccuracy = $row[osAccuracy];
					$osType = $row[osType];
					$osVendor = $row[osVendor];
					$osFamily = $row[osFamily];
					$osGen = $row[osGen];
					$osCPE = $row[osCPE];
				}
			
			
			
				foreach($host_stmt as $row){
				
					echo "<b>Scan performed: ".$row[scanType]."</b><br>";
					echo "Time scan was performed: ".$row[scanTime]."<br>";
					echo "Scan performed by: <b>".$username."</b><br><br>";
					echo "<b>Host Information </b><br><br>";
					echo "Host scanned: ".$row[hostName]." - ".$row[ipScanned]."<br>";
					echo "Host status at time of scan: ".$row[hostState]."<br>";
					echo "Host response: ".$row[hostReason]."<br>";
			
					if($row[hostip4Address]){
						echo "Host ipv4 Address: ".$row[hostip4Address]."<br>";
					}
					
					if($row[hostip6Address]){
						echo "Host ipv6 Address: ".$row[hostip6Address]."<br>";
					}
					
					if($row[hostmacAddress]){
						echo "Host MAC Address: ".$row[hostmacAddress]."<br>";
					}
					
					echo "Protocol Scanned: ".$row[protocol]."<br><br>";
					echo "<b>Port Information</b><br><br>";
					echo "Port scanned: ".$row[port]."<br>";
					echo "Port name: ".$row[portName]."<br>";
					echo "Port state: ".$row[portState]."<br>";
					echo "Port reason: ".$row[portReason]."<br>";
					
					if($row[product]){
						echo "Product: ".$row[product]."<br>";
					}
					
					if($row[version]){
						echo "version: ".$row[version]."<br>";
					}
					
					if($row[extrainfo]){
						echo "Extra information: ".$row[extrainfo]."<br>";
					}
					
					if($row[portCPE]){
						echo "CPE from NMAP.org: ".$row[portCPE]."<br>";
					}
					
					if($row[scriptOne]){
						echo "Script results: ".$row[scriptOne]."<br>";
					}
					
					if($row[scriptTwo]){
						echo "Script results: ".$row[scriptTwo]."<br>";
					}
				
					if($osName){
						echo "<br><b>OS Information</b><br><br>";
						echo "OS Name: ".$osName."<br>";
						echo "OS Accuracy: ".$osAccuracy."<br>";
						echo "OS Type: ".$osType."<br>";
						echo "OS Vendor: ".$osVendor."<br>";
						echo "OS Family: ".$osFamily."<br>";
						echo "OS Gen: ".$osGen."<br>";
						echo "CPE from NMAP.org: ".$osCPE."<br>";
					} else {
						
					}
				}
			?>
		</div>
	</body>
</html>