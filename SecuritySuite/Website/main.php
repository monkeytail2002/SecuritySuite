<?php session_start(); ?>
<html>
	<head>
	</head>
	
	<body>

		<?php
			
			$tool = $_POST['tools'];
			$scan = $_POST['scan'];
			$scanOption = $_POST['options'];
		
			$_SESSION['tool'] = $tool;
			$_SESSION['scan'] = $scan;
			$_SESSION['scanOption'] = $scanOption;
		
			if ($tool == Nmap){
				header('Location: http://176.58.101.211/nmap.php');
				die();
			} else {
				header('Location: http://176.58.101.211/index.html');
			}
			



		?>

		
	</body>
</html>