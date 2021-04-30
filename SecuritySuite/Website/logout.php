<!--
Jordan Laing
15009237
30/11/2020
logout.php - Signs the user out of the current session
-->

<?php
session_start();
?>

<?php

	session_destroy();
	header("Location:login.php");
?>