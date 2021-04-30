<!--
Angus MacDonald, Jordan Laing
15009351, 15009237
16/03/2021
main.php - Loads available search options for the users selected tool
(Option selection code by Angus, CSS and HTML element code by Jordan)
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
		<?php
			
			$tool = $_POST['tools'];
		
			$_SESSION['tool'] = $tool;

			if ($tool == nmap){
		?>
		
		<h1><center>Nmap Scan Configuration</center></h1>
		<br>
		<br>
		
		<div class="MainOptions">
		<form action="nmap.php" method="post">
			Scan Type: <select name="scan" id="scan">
			<option value="" selected ="selected">--Select scan--</option>
			</select>
			<br><br>
			Scan Options: <select name="options" id="options">
			<option value="" selected ="selected">--Select option--</option>
			</select>
			<br><br>
			<input class="CapButton" type="submit" value="Continue">
				
		</form>	
		</div>
		
			<script>
				var toolObject = {
					"Port": ["TCP", "TCP Syn", "UDP","SCTP","Null","Fin","Xmas","TCP/ACK","Advanced SCTP","IP"],
					"Banner Grab": ["Banner Grab", "Vulnerabilty Scan"],
					"Version Detection": ["Version detection - Intensity 0","Version detection - Intensity 1","Version detection - Intensity 2","Version detection - Intensity 3","Version detection - Intensity 4","Version detection - Intensity 5","Version detection - Intensity 6","Version detection - Intensity 7","Version detection - Intensity 8","Version detection - Intensity 9" ],
					"Operating System": ["Limited","Guess","Max tries - 1","Max tries - 2","Max tries - 3","Max tries - 4","Max tries - 5"],
					"NSE Scripts":["http-auth-finder","http-auth","http-enum","http-methods","http-sitemap-generator"]
				}
				
				window.onload = function() {
					var scanSel = document.getElementById("scan");
					var typeSel = document.getElementById("options");
					for (var x in toolObject){
						scanSel.options[scanSel.options.length] = new Option(x, x);
					}
					scanSel.onchange = function() {
						typeSel.length = 1;
						var z = toolObject[this.value];
						for (var i = 0; i < z.length; i++){
							typeSel.options[typeSel.options.length] = new Option(z[i], z[i]);
						}
					}
				}
			</script>
		<?php
			} else if($tool == metasploit) {
				?>
				
				<h1><center>Metasploit Scan Configuration</center></h1>
				<br>
				<br>
				
				<div class="MainOptions">
				<form action="metasploit.php" method="post">
					Module Information: <select name="module" id="module">
					<option value="" selected ="selected">--Select Module--</option>
					</select>
					<br><br>
					Module group: <select name="group" id="group">
					<option value="" selected="selected">--Select Group--</option></select>
					<br><br>
					<input class="CapButton" type="submit" value="Execute">				
				</form>	
				</div>
				
				<script>				
					var metaObject = {
						"Exploits": ["aix", "android", "apple_ios","bsd","bsdi","dialup","firefox","freebsd","hpux","irix", "linux", "mainframe", "multi", "netware", "openbsd", "osx", "qnx", "solaris", "unix", "windows"],
						"Payloads": ["aix", "android", "apple_ios","bsd","bsdi","cmd","firefox","generic","java", "linux", "mainframe", "multi", "netware", "nodejs", "osx", "php", "python", "r", "ruby", "solaris", "tty", "windows"],
						"Auxiliaries": ["admin","analyze","bnat","client","cloud","crawler","docx","dos","fileformat","fuzzers","gather","parser","pdf","scanner","server","sniffer","spoof","sqli","voip","vsploit"],
						"No Operations": ["aarch64","armle","mipsbe","php","ppc","sparc","tty","x64","x86"],
						"Encoders":["cmd","generic","mipsbe","php","ppc","ruby","sparc","x64","x86"],
						"Posts":["aix","android","apple_ios","bsd","bsdi","cmd","firefox","generic","java","linux","mainframe","multi","netware","nodejs","osx","php","python","r","ruby","solaris","tty","windows"]
					}
					
					window.onload = function() {
						var modSel = document.getElementById("module");
						var groupSel = document.getElementById("group");
						for (var x in metaObject){
							modSel.options[modSel.options.length] = new Option(x, x);
						}
						modSel.onchange = function() {
							groupSel.length = 1;
							var z = metaObject[this.value];
							for (var i = 0; i < z.length; i++){
								groupSel.options[groupSel.options.length] = new Option(z[i], z[i]);
							}
						}
					}
				</script>
		<?php
			} else {
				
				header('Location: index.php');
			}
		?>
		
		<footer>
		
			<p class="FooterElements">&#169; Copyright [Placeholder] 2021</p>
				<div class="FooterElements">
				
					<a href="legal.html">Legal Information</a>
					<a href="sitemap.html">Sitemap</a>
				</div>
		</footer>
	</body>
	

</html>