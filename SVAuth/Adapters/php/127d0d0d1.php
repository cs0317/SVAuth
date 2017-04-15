<script>
  <?php 
   session_start();
   if ($_SESSION["SVAuth_UserID"]!=null && $_SESSION["SVAuth_UserID"]!="") { 
      echo "top.location.href=\"AllInOne.php\";";
   }
?>
</script>
