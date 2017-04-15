<?php
session_start();
session_unset();
session_destroy();
?>
Hello <?php echo $_GET['UserID']; ?> <br>
Current <?php  echo $_SESSION["SVAuth_UserID"]; ?> <br>
SESSID <?php  echo $_COOKIE["PHPSESSID"]; ?>


 