<?php
$json_string = file_get_contents("../resources/config.json");
$config = json_decode($json_string, true);

if (strcmp($config['AgentSettings']['agentScope'],'local')==0) {
  echo "The agent\'s agentScope is \'local\'. Please directly redirect the browser to one of the local entry points, such as https://thisMachine.com:3000/login/Facebook.";
  exit(0);
}
echo $config['AgentSettings']['agentScope'];
session_start();
echo session_id() . "<br>" ;
echo hash('sha256',session_id());
$req = $config['AgentSettings']['scheme'] . "://" . $config['AgentSettings']['agentHostname'] . ":" . $config['AgentSettings']['port'];
$req = $req . "/login/" . $_GET["provider"] . "?conckey=" . substr(hash('sha256',session_id()),strlen(session_id())) ;
$req = $req . "&concdst=" . $config['WebAppSettings']['scheme'] . "://" . $config['WebAppSettings']['hostname'] . ":" . $config['WebAppSettings']['port'] . $config['WebAppSettings']['rootPath'];
echo "<br>" . $req;
header ("location: " . $req);
?>


 