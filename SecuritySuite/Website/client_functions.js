//Jordan Laing
//15009237
//26/04/2021
//client_functions.js - Store all Javascript functions used by the website

//Checks if the user has been passed back to the page with an error message
function displayAlert() {
	
	var checkAlert=getCookie('Site_Message');
	
	if(checkAlert) {
		//Display the message and replace any space character encoding, '%20', with a space
		alert(checkAlert.replace(/%20/g,' '));
		//once the message has been displayed, set a past expiry date for the cookie to delete it
		document.cookie = "Site_Message= ; expires = Thu, 01 Jan 1970 00:00:00 GMT";
	}
}


//Finds the value of the cookie passed as parameter 'cookieName'
//Code based on the cookie get function on w3schools (https://www.w3schools.com/js/js_cookies.asp )
function getCookie(cookieName) {
	
	var name = cookieName + "=";
	var ca = document.cookie.split(';');
	
	for(var i = 0; i < ca.length; i++) {
		var c = ca[i];
		while (c.charAt(0) == ' ') {
			c = c.substring(1);
		}
		if (c.indexOf(name) == 0) {
			return c.substring(name.length, c.length);
		}
	}
	return "";
}


//Checks whether the password & confirm password fields in the new user registration form match
//Code based on the form validation function on w3schools  (https://www.w3schools.com/js/js_validation.asp )
function comparePass() {
	
	var newPass = document.getElementById("newPassword").value;
	var confPass = document.getElementById("confirmPassword").value;
	
	if((newPass == confPass)){
		return true;
	} else {
		alert("Password and confirm password do not match!");
		return false;
	}
}


//Runs on form pages to tell the server if the user has javascript enabled
function scriptCheck(elementID) {
	
	var scriptInput = document.getElementById(elementID).value= "Y";
};