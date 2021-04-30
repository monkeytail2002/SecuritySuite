<!--
Jordan Laing, Angus MacDonald
15009237, 15009351
26/03/2021
DbConnect.php - Store database connection information 
(initial SQLi code by Jordan, PDO code by Angus)
-->
<?php
	$DB_USER = '';
	$DB_PASSWORD = '';
	$DB_HOST = 'localhost'; 
	$DB_NAME = '';
	$charset = 'utf8mb4';
	

//Set the dsn details
	$dsn = "mysql:host=$DB_HOST;dbname=$DB_NAME;charset=$charset";
//Set the options
	$options = array(
		PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
		PDO::ATTR_DEFAULT_FETCH_MODE =>PDO::FETCH_ASSOC,	
		PDO::ATTR_EMULATE_PREPARES => false,
		);

////connect
	try {
		$db = new PDO($dsn, $DB_USER, $DB_PASSWORD, $options);
	} catch (\PDOException $e){
		throw new \PDOException($e->getMessage(), (int)$e->getCode());
	}


?>
