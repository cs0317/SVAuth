<?php
session_start();
session_destroy();
?>
Hello <?php echo $_GET['UserID']; ?> <br>
Current <?php  echo $_SESSION['UserID']; ?> <br>
SESSID <?php  echo $_COOKIE["PHPSESSID"]; ?>
<?php  header('Location: /');
?>

 