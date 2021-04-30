<!--
Jordan Laing
15009237
16/04/2021
index.php - Main landing page after user sign in, contains tool selection and previous searches table
-->

<?php 
	session_start();
	include('DbConnect.php');
?>

<html>
	<head>
		<title>Security Suite</title>
		
		<!-- Link to the CSS file that drives the page formatting/style -->
		<link href="jomanji_style.css" type="text/css" rel="stylesheet" />
		
		<?php 
			include ("jomanjifunctions.php");
			checkActiveSession();
		?>
		
	</head>
	
	<body onload="displayAlert()">
		<div class="container">
		
			<div class="PageHeader">
				
				<p class="HeaderLeft"><a href="index.php"><img id="companyLogo" src="img/logo.png" alt="index.php"></a></p>
					
				<div class="HeaderRight"><a href="account.php"><figure><img id="accountLogo"src="img/account.png" alt="account.php"><figcaption>My Account</figcaption></figure></a></div>
			</div>	

			<h1><center>Security Suite</center></h1>
			<br>
			<br>
			
			<div class="ToolSelection">
			
				<h2>Select a tool</h2>
				<form action="main.php" method="post">
					Tools: <select name="tools" id="tools">
					<option value="" selected="selected">--Select tool--</option>
					<option value="nmap">Nmap</option>
					<option value="metasploit">Metasploit</option>
					</select>
					<br><br>
					<input class="CapButton" type="submit" value="Continue">
				</form>	
			</div>
			
			<div class ="PreviousSearches">
			
				<h2><center>Last 10 Nmap Scans</center></h2>
				
				<div class="RecentTable">
					
					<?php
					
						$scan_stmt = $db->query("SELECT scan.scanTime, scan.scanType, scan.scanID, hosts.hostName FROM scan JOIN hosts ON scan.hostID = hosts.hostID ORDER BY scanTime DESC LIMIT 10")->fetchAll();
					?>
				
					<form action="previousresults.php" method="post">
						<table id="recentResultsTable">
							<tr>
								<th>Date</th>
								<th>Scan Type</th>
								<th>Target</th>
								<th>Results</th>

							</tr>
							
							<?php
								foreach($scan_stmt as $row){
									echo "<tr>"."<td>".$row[scanTime]."</td>"."<td>".$row[scanType]."</td>"."<td>".$row[hostName]."</td>"."<td><a class='CapButton' href='previousresults.php?q=".$row[scanID]."'>View</a></td></tr>";					
								}
							?>
						</table>
					</form>	
				</div>
			</div>
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