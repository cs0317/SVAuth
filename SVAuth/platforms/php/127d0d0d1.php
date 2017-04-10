<script>
  <?php 
   session_start();
   if ($_SESSION['UserID']!=null && $_SESSION['UserID']!="") { 
      echo "top.location.href=\"AllInOne.php\";";
   }
?>
</script>
