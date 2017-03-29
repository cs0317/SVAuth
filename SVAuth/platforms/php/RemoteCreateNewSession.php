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
	//echo $decrypted . "<<<<";
	$conc = json_decode($decrypted,true);
	var_dump($conc);
	echo "LoginPageUrl" . $_COOKIE["LoginPageUrl"];
	echo "session id1 is " . session_id() . "<br>";
    echo ($_SESSION['email'] . "<<<" . $conc['Email']) . ">>>";
	session_unset();
  //  session_destroy();
//	session_write_close();
	$_SESSION['email'] = $conc['Email'];
	$_SESSION['UserID'] = $conc['UserID'];
	$_SESSION['FullName'] = $conc['FullName'];
	setcookie(session_name(),'',0,'/');
    session_regenerate_id(true);
	echo "session id2 is " . session_id() . "<br>";
    //session_start();
	//$_SESSION['email'] = $conc["Email"];
  echo "session id2 is " . session_id() . "<br>";
  echo ("location:" . $_COOKIE["LoginPageUrl"] );
	header ("location:" . $_COOKIE["LoginPageUrl"] );
  
?>
 