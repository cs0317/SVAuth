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
Session["foo"]=1;
var session_id=System.Web.HttpContext.Current.Session.SessionID;
Response.Write( "session_id=" + session_id +"<br>");
HashAlgorithm hashAlgo = SHA256.Create();
byte[] conckey_bytes=hashAlgo.ComputeHash(System.Text.Encoding.UTF8.GetBytes(session_id));
string conckey = BitConverter.ToString(conckey_bytes).Replace("-","");

if (config["AgentSettings"]["agentHostname"]=="localhost" && Request.QueryString["provider"]=="Weibo") {
     config["AgentSettings"]["agentHostname"] = "127.0.0.1";
}
if (config["WebAppSettings"]["hostname"]=="localhost" && Request.QueryString["provider"]=="Weibo") {
     config["WebAppSettings"]["hostname"] = "127.0.0.1";
     HttpCookie LoginPageUrl = new HttpCookie("LoginPageUrl", "; path=/; expires=Thu, 01-Jan-70 00:00:01 GMT;");
     Response.Cookies.Add(LoginPageUrl);
     LoginPageUrl = new HttpCookie("LoginPageUrl", HttpContext.Current.Request.Url.Scheme+"://"+ HttpContext.Current.Request.Url.Authority + "/SVAuth/platforms/aspx/AllInOne.aspx; path=/; ");
     Response.Cookies.Add(LoginPageUrl);
}
string req = config["AgentSettings"]["scheme"] + "://" + config["AgentSettings"]["agentHostname"] + ":" + config["AgentSettings"]["port"];
req += "/login/" + Request.QueryString["provider"] + "?conckey=" + conckey ;
req += "&concdst=" + config["WebAppSettings"]["scheme"] + "://" + config["WebAppSettings"]["hostname"] + ":" + config["WebAppSettings"]["port"] + "?" + config["WebAppSettings"]["platform"]["name"];

Response.Redirect(req);
%>

 