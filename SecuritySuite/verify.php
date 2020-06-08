<?php require_once('config.php');?>


<!DOCTYPE html>
<html lang - "en">
	<head>
		<title>verify user</title>
	</head>
	<body>
		<?php
		
		$username = mysqli_real_escape_string($conn, $_POST['username']);
		$user_password = mysqli_real_escape_string($conn, $_POST['password']);
		$needed_tool = mysqli_real_escape_string($conn, $POST['tools']);	
		
		$Query = "SELECT * FROM Users WHERE Username = '$username'";
		$Result = mysqli_query($conn,$Query);
		$NumResults = mysqli_num_rows($Result);	
		
		if ($NumResults==1){
			$Result = mysqli_query($conn,$Query);
			$Row = mysqli_fetch_assoc($Result);
			$user_id = $Row['UserId'];
			$email = $Row['Email'];
			$username = $Row['Username'];
			$hashed_password = $Row['Password'];
			$user_level = $Row['Role'];
			$twit_scrape = $Row['TwScrape'];
			$nmap = $Row['Nmap'];
			
			//Verify the password entered.
			if (password_verify($user_password,$hashed_password)){
				$_SESSION["UserId"] = $user_id;
				$_SESSION["Email"] = $email;
				$_SESSION["UserName"] = $username;
				$_SESSION["Valid"] = 'True';
				$_SESSION["UserLevel"] = $user_level;
				$_SESSION["HP"] = $hashed_password;
				$_SESSION['susp'] = $Row['Suspended'];
				setcookie('Current_user',$username);
				
				
				if($needed_tool == $twit_scrape){
					echo "<script type='text/javascript'>alert('Logging you in to the Twitter URL Scraper now');
					window.location='Twitter.php';
					</script>";
				} else if ($needed_tool == $nmap) {
					echo "<script type='text/javascript'>alert('Logging you in to the Nmap Scanner now');
					window.location='nmap.php';
					</script>";
				}
			} else {
				echo "<script type='text/javascript'>alert('Incorrect username or password.  Please try again');
				window.location='index.php';
				</script>";
			}
		} else {
			echo "<script type='text/javascript'>alert('User not found');
			window.location='index.php';
			</script>";
		}
		?>
	</body>
</html>
