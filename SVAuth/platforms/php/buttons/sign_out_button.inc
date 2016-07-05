<?php session_start(); ?> 
<?php
if ((strlen($_SESSION['UserID'])>0)) { ?>
  <script>
  function clearSession() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
    if (xhttp.readyState == 4) {
	 location.reload();
    }
  };
  xhttp.open("GET", "sign_out.php", true);
  xhttp.send();
 }
 </script>
  <img OnClick="clearSession();" src="/SVAuth/images/Sign_out.jpg" width=40 height=40 oncontextmenu="copyToClipboard('&lt;?php include dirname($_SERVER[&#34;PATH_TRANSLATED&#34;]).&#34;\\buttons\\sign_out_button.inc&#34; ?&gt;');return false;"/>
<?php } ?>
