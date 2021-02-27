
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
		
			$ipRange = $_POST['ipRange'];
			$ports = $_POST['ports'];
			$chosenScan = $_SESSION['chosenScan'];

		
			$python_return = shell_exec("sudo /var/www/html/jobs.sh $ipRange~$ports~$chosenScan");
				
	
		$python_return = str_replace(array("u'","[","]"), array(""), $python_return);

		
		$str_to_php_array = str_getcsv($python_return, ",");
		$return_1 = trim($str_to_php_array[0], " '");
		$return_2 = trim($str_to_php_array[1], " '");
		$return_3 = trim($str_to_php_array[2], " '");
		$return_4 = trim($str_to_php_array[3], " '");
		$return_5 = trim($str_to_php_array[4], " '");
		$return_6 = trim($str_to_php_array[5], " '");
		$return_7 = trim($str_to_php_array[6], " '");
		$return_8 = trim($str_to_php_array[7], " '");
		$return_9 = trim($str_to_php_array[8], " '");
		$return_10 = trim($str_to_php_array[9], " '");
		
		echo $return_1;
		echo "<br>";
		echo $return_2;
		echo "<br>";
		echo $return_3;
		echo "<br>";
		echo $return_4;
		echo "<br>";
		echo $return_5;
		echo "<br>";
		echo $return_6;
		echo "<br>";
		echo $return_7;
		echo "<br>";
		echo $return_8;
		echo "<br>";
		echo $return_9;
		echo "<br>";
		echo $return_10;
		echo "<br>";

		

		?>
		
	</body>
</html>