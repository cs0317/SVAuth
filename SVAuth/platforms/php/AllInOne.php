<html>

<head>

<style>
#grad1 {
    background: blue; /* For browsers that do not support gradients */    
    background: -webkit-linear-gradient(left, blue , green); /* For Safari 5.1 to 6.0 */
    background: -o-linear-gradient(right, blue, green); /* For Opera 11.1 to 12.0 */
    background: -moz-linear-gradient(right, blue, green); /* For Firefox 3.6 to 15 */
    background: linear-gradient(to right, blue , green); /* Standard syntax (must be last) */
}
</style>
</head>
<?php
$json_string = file_get_contents("../resources/config.json");
$config = json_decode($json_string, true);

if (strcmp($config['AgentSettings']['agentScope'],'local')==0) {
	$scheme = $config['AgentSettings']['scheme'];
    $port=$config['AgentSettings']['port'];
} else {
	$scheme = $config['WebAppSettings']['scheme'];
    $port=$config['WebAppSettings']['port'];
}
?>

<body>
<script>
      function login_start(provider) {
	      scheme = <?php echo "'". $scheme . "'" ?>;
		  port = <?php echo "'". $port . "'" ?>;
		  document.cookie="LoginPageUrl=; path=/; expires=Thu, 01-Jan-70 00:00:01 GMT;";
		  document.cookie="LoginPageUrl="+location+";path=/";
		  hostname = location.host;
		  if (provider.toLowerCase() === "Weibo".toLowerCase()) {
		      <?php if (strcmp($config['AgentSettings']['agentHostname'],'localhost')==0) {
                      echo "hostname=\"127.0.0.1\";\n";
                    }
			  ?>
		   }
		  url=scheme+"://"+hostname + ":"+ port+
		      <?php if (strcmp($config['AgentSettings']['agentScope'],'local')==0) {
	                   echo "'/login/'+provider;";
					} else {  
					     echo "'/SVAuth/platforms/php/start.php?provider='+provider;";
					}
			  ?>	 
		  window.location=url;
	  }

  function clearSession() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
        if (xhttp.readyState == 4) {
		    <?php  
				if ($_SERVER['HTTP_HOST']=="127.0.0.1") { 
				    echo "location.href=\"" . $config['WebAppSettings']['scheme'] . "://localhost:" . $config['WebAppSettings']['port'] . $_SERVER['REQUEST_URI'] ."\""; 
				} else  {
	                echo "location.reload();";
				}
			?>
	      
        }
    };
    xhttp.open("GET", "sign_out.php", true);
    xhttp.send();
  }
</script>
<?php
// Start the session
session_start();
$providers = array('Facebook', 'Microsoft', 'MicrosoftAzureAD', 'Google', 'Yahoo', 'Weibo','WeChat');
?>
<div id="grad1">
<?php if ($_SESSION['UserID']!=null) { ?>
    <img OnClick="clearSession();" src="../resources/images/sign_out.jpg" width=40 height=40>
<?php } else { 
   foreach ($providers as $provider) {
       echo "<img OnClick=\"login_start('" . 
	           $provider . 
		    "');\" src=\"../resources/images/" .
			   $provider . 
			"_login.jpg\" width=100 height=40>";
     }
   }
?>
</div>

<h3>User identity bound to this session (<?php echo session_id() ?>):<br /></h3>

<font face="Courier New" size=2>
 Session["UserID"]=<?php echo $_SESSION['UserID']; ?> <br />
 Session["FullName"]=<?php echo $_SESSION['FullName']; ?> <br />
 Session["email"]=<?php echo $_SESSION['email']; ?> <br />
</font>
<br />


<?php  
   /* because weibo doesn't allow localhost to be the redirect_uri */
   if ($_SERVER['HTTP_HOST']=="localhost") {  
      echo "<iframe style=\"display: none;\" src=\""
	        . $config['WebAppSettings']['scheme']
			. "://127.0.0.1:" 
	        . $config['WebAppSettings']['port']
			. "/SVAuth/platforms/php/127d0d0d1.php\""
	        . "></iframe>";
   } 
?> 
</body>
</html>
