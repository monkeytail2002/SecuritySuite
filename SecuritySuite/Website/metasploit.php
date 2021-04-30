<!--
Angus MacDonald, Jordan Laing
15009351, 15009237
22/03/2021
metasploit.php - Runs selected metasploit lookup and returns results
(Python and return loops by Angus, CSS and HTML element code by Jordan)
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
		
		<div class="container">
			<h1><center>Metasploit Database Information</center></h1>
			<br><br>
		</div>
		
		
		<?php
		
			$metaModule = $_POST['module'];
			$metaGroup = $_POST['group'];
		
		$combi = $metaModule."~".$metaGroup;
//		echo $combi;

			
			if($metaModule=="Exploits") {
				$python_return = shell_exec("sudo /home/michelangelo/SecShell/metajob.sh $combi");
//							echo $python_return;
				$return_object = json_decode($python_return, true);
//							print_r($return_object);
				$meta_return = $return_object[0];
				
				foreach($meta_return as $exploit => $i){
					echo '<div class="MetasploitItem">';
					echo '<b>Exploit</b>: '.$i['exploit'].'<br><br>';
					echo '<b>Description</b>: '.$i['description'].'<br><br>';
					echo '<b>Authors</b>: <br>';
					foreach ($i['authors'] as $author => $j){
						echo '<p class="MetaList">'.$j['author'].'</p>';
					}
					echo '<br><b>Required Options</b>: <br>';
					foreach ($i['required'] as $required => $k){
						echo '<p class="MetaList">'.$k['required'].'</p>';
					}
					echo '<br><b>Available Options</b>: <br>';
					foreach ($i['options'] as $option => $l){
						echo '<p class="MetaList">'.$l['option'].'</p>';
					}
					echo '<br><b>Payloads for Exploit</b>: <br>';
					foreach ($i['payloads'] as $required => $m){
						echo '<p class="MetaList">'.$m['payload'].'</p>';
					}
					echo '</div>';
					echo '<br><br>';
				}
			}
			else if($metaModule == "Payloads"){
//				echo $combi;
				$python_return = shell_exec("sudo /home/michelangelo/SecShell/metajob.sh $combi");
//							echo $python_return;
				$return_object = json_decode($python_return, true);
				//			print_r($return_object);
				$meta_return = $return_object[0];
				
				foreach($meta_return as $payload => $i){
					echo '<div class="MetasploitItem">';
					echo '<b>Payload</b>: '.$i['payload'].'<br><br>';
					echo '<b>Description</b>: '.$i['description'].'<br><br>';
					echo '<b>Authors</b>: <br>';
					foreach ($i['authors'] as $author => $j){
						echo '<p class="MetaList">'.$j['author'].'</p>';
					}
					echo '<br><b>Required Options</b>: <br>';
					foreach ($i['required'] as $required => $k){
						echo '<p class="MetaList">'.$k['required'].'</p>';
					}
					echo '<br><b>Available Options</b>: <br>';
					foreach ($i['options'] as $option => $l){
						echo '<p class="MetaList">'.$l['option'].'</p>';
					}
					echo '</div>';
					echo '<br><br>';
				}
				
			}
			else if($metaModule == "Auxiliaries"){
//					echo $combi;
					$python_return = shell_exec("sudo /home/michelangelo/SecShell/metajob.sh $combi");
//							echo $python_return;
					$return_object = json_decode($python_return, true);
				//			print_r($return_object);
					$meta_return = $return_object[0];
				
					foreach($meta_return as $Auxiliaries => $i){
						echo '<div class="MetasploitItem">';
						echo '<b>Auxiliaries</b>: '.$i['auxiliary'].'<br><br>';
						echo '<b>Description</b>: '.$i['description'].'<br><br>';
						echo '<b>Authors</b>: <br>';
						foreach ($i['authors'] as $author => $j){
							echo '<p class="MetaList">'.$j['author'].'</p>';
						}
						echo '<br><b>Required Options</b>: <br>';
						foreach ($i['required'] as $required => $k){
							echo '<p class="MetaList">'.$k['required'].'</p>';
						}
						echo '<br><b>Available Options</b>: <br>';
						foreach ($i['options'] as $option => $l){
							echo '<p class="MetaList">'.$l['option'].'</p>';
						}
						echo '</div>';
						echo '<br><br>';
					}
				
				}
			else if($metaModule == "Nops"){
//						echo $combi;
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/metajob.sh $combi");
//								echo $python_return;
						$return_object = json_decode($python_return, true);
//								print_r($return_object);
						$meta_return = $return_object[0];
						
						foreach($meta_return as $nops => $i){
							echo '<div class="MetasploitItem">';
							echo '<b>No Operations</b>: '.$i['nops'].'<br><br>';
							echo '<b>Description</b>: '.$i['description'].'<br><br>';
							echo '<b>Authors</b>: <br>';
							foreach ($i['authors'] as $author => $j){
								echo '<p class="MetaList">'.$j['author'].'</p>';
							}
							echo '<br><b>Available Options</b>: <br>';
							foreach ($i['options'] as $option => $l){
								echo '<p class="MetaList">'.$l['option'].'</p>';
							}
							echo '</div>';
							echo '<br><br>';
						}
//				
			}
			else if($metaModule == "Encoders"){
//						echo $combi;
						$python_return = shell_exec("sudo /home/michelangelo/SecShell/metajob.sh $combi");
//								echo $python_return;
						$return_object = json_decode($python_return, true);
				//				print_r($return_object);
						$meta_return = $return_object[0];
				
						foreach($meta_return as $encoders => $i){
							echo '<div class="MetasploitItem">';
							echo '<b>Encoder</b>: '.$i['encoders'].'<br><br>';
							echo '<b>Description</b>: '.$i['description'].'<br><br>';
							echo '<b>Authors</b>: <br>';
							foreach ($i['authors'] as $author => $j){
								echo '<p class="MetaList">'.$j['author'].'</p>';
							}
							echo '<br><b>Available Options</b>: <br>';
							foreach ($i['options'] as $option => $l){
								echo '<p class="MetaList">'.$l['option'].'</p>';
							}
							echo '</div>';
							echo '<br><br>';
						}
//				
			}
			else if($metaModule == "Posts"){
//					echo $combi;
					$python_return = shell_exec("sudo /home/michelangelo/SecShell/metajob.sh $combi");
//							echo $python_return;
					$return_object = json_decode($python_return, true);
				//			print_r($return_object);
					$meta_return = $return_object[0];
				
					foreach($meta_return as $posts => $i){
						echo '<div class="MetasploitItem">';
						echo '<b>Posts</b>: '.$i['posts'].'<br><br>';
						echo '<b>Description</b>: '.$i['description'].'<br><br>';
						echo '<b>Authors</b>: <br>';
						foreach ($i['authors'] as $author => $j){
							echo '<p class="MetaList">'.$j['author'].'</p>';
						}
						echo '<br><b>Required Options</b>: <br>';
						foreach ($i['required'] as $required => $k){
							echo '<p class="MetaList">'.$k['required'].'</p>';
						}
						echo '<br><b>Available Options</b>: <br>';
						foreach ($i['options'] as $option => $l){
							echo '<p class="MetaList">'.$l['option'].'</p>';
						}
						echo '</div>';
						echo '<br><br>';
					}
				}
		?>
		
	</body>
</html>