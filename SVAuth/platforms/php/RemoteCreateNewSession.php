<?php
    session_start();
	$hex = hex2bin($_GET['encryptedUserProfile']);
    //echo bin2hex($hex[0]) . "-" . bin2hex($hex[271]);
	$key = substr(hash('sha256',session_id()),strlen(session_id()));
	$key = utf8_encode($key).substr(256 / 8);
	// echo bin2hex($key[0]) . "-" . bin2hex($key[31]);
	$IV = utf8_encode($key).substr(128 / 8);
    $decrypted = openssl_decrypt (
         $hex, "AES-256-CBC", $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,$IV
    );
	$endpos=strpos($decrypted,"}"); 
	$decrypted= substr($decrypted,0,$endpos+1) ;
	echo $decrypted . "<<<<";
	$conc = json_decode($decrypted,true);
	var_dump($conc);
	echo "LandingUrl" . $_COOKIE["LandingUrl"];
	echo "session id1 is " . session_id() . "<br>";
	session_unset();
  //  session_destroy();
//	session_write_close();
	$_SESSION["SVAuth_Email"] = $conc['Email'];
	$_SESSION["SVAuth_UserID"] = $conc['UserID'];
	$_SESSION["SVAuth_FullName"] = $conc['FullName'];
  $_SESSION["SVAuth_Authority"] = $conc['Authority'];
	setcookie(session_name(),'',0,'/');
    session_regenerate_id(true);
	echo "session id2 is " . session_id() . "<br>";
    //session_start();
  echo "session id2 is " . session_id() . "<br>";
  echo ("location:" . $_COOKIE["LandingUrl"] );
	header ("location:" . $_COOKIE["LandingUrl"] );
  
?>
 