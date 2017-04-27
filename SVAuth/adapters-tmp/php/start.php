<?php
echo "start <br>";
$json_string = file_get_contents("../adapter_config/adapter_config.json");
$config = json_decode($json_string, true);

session_start();
echo session_id() . "<br>" ;
echo hash('sha256',session_id());

if (strcmp($config['AgentSettings']['agentHostname'],'localhost')==0 && strcmp($_GET["provider"],'Weibo')==0) {
     $config['AgentSettings']['agentHostname'] = "127.0.0.1";
}
if (strcmp($config['WebAppSettings']['hostname'],'localhost')==0 && strcmp($_GET["provider"],'Weibo')==0) {
     $config['WebAppSettings']['hostname'] = "127.0.0.1";
     $cookieValue = $config['WebAppSettings']['scheme'] . "://localhost:" .  $config['WebAppSettings']['port'] . "/SVAuth/adapters/php/AllInOne.php";
     setcookie("LandingUrl", $cookieValue, 0 ,"/"); 
     echo $cookieValue;
}
$req = $config['AgentSettings']['scheme'] . "://" . $config['AgentSettings']['agentHostname'] . ":" . $config['AgentSettings']['port'];
$req = $req . "/login/" . $_GET["provider"] . "?conckey=" . substr(hash('sha256',session_id()),strlen(session_id())) ;
$req = $req . "&concdst=" . $config['WebAppSettings']['scheme'] . "://" . $config['WebAppSettings']['hostname'] . ":" . $config['WebAppSettings']['port'] . "?" . $config['WebAppSettings']["platform"]["name"];
echo "<br>" . $req;
header ("location: " . $req);
?>


 