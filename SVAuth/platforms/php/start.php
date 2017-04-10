<?php
$json_string = file_get_contents("../config/config.json");
$config = json_decode($json_string, true);

if (strcmp($config['AgentSettings']['agentScope'],'local')==0) {
  echo "The agent\'s agentScope is \'local\'. Please directly redirect the browser to one of the local entry points, such as https://thisMachine.com:3000/login/Facebook.";
  exit(0);
}
echo $config['AgentSettings']['agentScope'];
session_start();
echo session_id() . "<br>" ;
echo hash('sha256',session_id());

if (strcmp($config['AgentSettings']['agentHostname'],'localhost')==0 && strcmp($_GET["provider"],'Weibo')==0) {
     $config['AgentSettings']['agentHostname'] = "127.0.0.1";
}
if (strcmp($config['WebAppSettings']['hostname'],'localhost')==0 && strcmp($_GET["provider"],'Weibo')==0) {
     $config['WebAppSettings']['hostname'] = "127.0.0.1";
     $cookieValue = $config['WebAppSettings']['scheme'] . "://localhost:" .  $config['WebAppSettings']['port'] . "/SVAuth/platforms/php/AllInOne.php";
     setcookie("LoginPageUrl", $cookieValue, 0 ,"/"); 
     echo $cookieValue;
}
$req = $config['AgentSettings']['scheme'] . "://" . $config['AgentSettings']['agentHostname'] . ":" . $config['AgentSettings']['port'];
$req = $req . "/login/" . $_GET["provider"] . "?conckey=" . substr(hash('sha256',session_id()),strlen(session_id())) ;
$req = $req . "&concdst=" . $config['WebAppSettings']['scheme'] . "://" . $config['WebAppSettings']['hostname'] . ":" . $config['WebAppSettings']['port'] . "?" . $config['WebAppSettings']["platform"]["name"];
echo "<br>" . $req;
header ("location: " . $req);
?>


 