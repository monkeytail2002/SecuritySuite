<!--Required modules-->
<?php require_once('config.php') ?>
<?php require_once( ROOT_PATH . '/includes/public_functions.php') ?>
<?php require_once( ROOT_PATH . '/includes/logout.php') ?>
<?php require_once( ROOT_PATH . '/includes/head_section.php') ?>



<title>Sign in| Security Suite </title>
</head>
<body>

	<div class="container">
		
<!-- banner with log in-->
	<div class="banner">
		<div class="welcome_msg">
			<h1>Security Suite</h1>
		</div>


	</div>
		

		
		<!-- Page content -->
		<div class="content">
			<h2 class="content-title">Please sign in to use the tools within the suite</h2>
            
            <div class="login_div">
				<form action="verify.php" method="post" >
					<h2>Login</h2>
					<input type="text" name="username" value="<?php echo $username; ?>" placeholder="Username">
					<input type="password" name="password"  placeholder="Password">
					<br><p>Please choose the Tool that you need today</p>
					<select name="tools">
						<option value="" selected hidden>--Action-- </option>
						<option value="1">Twitter URL Scanner</option>
						<option value="2">Nmap Scanner</option>
					</select>
					<br>
					<button class="btn" type="submit" name="login_btn">Sign in</button>
            	</form>
                <br><br>
                <p>If you are not registered then click register:</p>
                <button id="registerButton" class="btn">Register</button>
		    </div>
		
		</div>
	</div>
    
    <script type="text/javascript">
        document.getElementById("registerButton").onclick = function () {
            location.href = "https://comp-hons.uhi.ac.uk/~15009351/TestGraded/Register.php";
        }
    
    </script>
        
        
<?php require_once( ROOT_PATH . '/includes/footer.php') ?>