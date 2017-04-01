<%@ Page Language="C#" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace= "System.Security.Cryptography" %>
<% 
var jsonString = File.ReadAllText(Request.PhysicalPath+"/../../resources/config.json");
JavaScriptSerializer js = new JavaScriptSerializer();
dynamic config = js.Deserialize<dynamic>(jsonString);
if (String.Compare(config["AgentSettings"]["agentScope"],"local")==0) {
  Response.Write( "The agent\'s agentScope is \'local\'. Please directly redirect the browser to one of the local entry points, such as https://thisMachine.com:3000/login/Facebook. <br>");
  Response.End();
}
var session_id=System.Web.HttpContext.Current.Session.SessionID;
HashAlgorithm hashAlgo = SHA256.Create();
byte[] conckey_bytes=hashAlgo.ComputeHash(System.Text.Encoding.UTF8.GetBytes(session_id));
string conckey = BitConverter.ToString(conckey_bytes).Replace("-","");
conckey = conckey.Substring(0,conckey.Length);
string req = config["AgentSettings"]["scheme"] + "://" + config["AgentSettings"]["agentHostname"] + ":" + config["AgentSettings"]["port"];
req += "/login/" + Request.QueryString["provider"] + "?conckey=" + conckey ;
req += "&concdst=" + config["WebAppSettings"]["scheme"] + "://" + config["WebAppSettings"]["hostname"] + ":" + config["WebAppSettings"]["port"] + "?" + config["WebAppSettings"]["platform"]["name"];
//header ("location: " . req);               
Response.Redirect(req);
%>

 