<?php
// Start the session
session_start();
?>
Hello <?php echo $_POST['Email']; ?> <br>
Current <?php  echo $_SESSION['UserID']; ?> <br>
SESSID <?php  echo $_COOKIE["PHPSESSID"]; ?>
<?php
	if ($_SERVER['REMOTE_ADDR'] != "127.0.0.1" and $_SERVER['REMOTE_ADDR'] != "::1"){
        // TODO: return 403 error
        echo "local access only";
        return;
    }
    $UserID = $_POST['UserID'];
	$FullName = $_POST['FullName'];
	$email = $_POST['Email'];
	if (!(strlen($UserID) > 0)) {
		echo "before abandon:",$_COOKIE["PHPSESSID"];
		unset($_SESSION['UserID']);
		unset($_SESSION['FullName']);
		unset($_SESSION['email']);
		session_destroy();
		echo "after abandon:",$_COOKIE["PHPSESSID"];
		return;
	}
    else {
   	    session_regenerate_id();
        $new_sessionid = session_id();

        $_SESSION['UserID'] = $UserID;
        $_SESSION['FullName'] = $FullName;
        $_SESSION['email'] = $email;
		//setcookie("PHPSESSID", $new_sessionid,0, "/");
		echo "set vars (",$_SESSION['UserID'],")(",$_COOKIE["PHPSESSID"],")(",$new_sessionid,")";
    }
?>
 