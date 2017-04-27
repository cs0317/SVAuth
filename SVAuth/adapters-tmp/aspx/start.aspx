<%@ Page Language="C#" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace= "System.Security.Cryptography" %>
<% 
var jsonString = File.ReadAllText(Request.PhysicalPath+"/../../adapter_config/adapter_config.json");
JavaScriptSerializer js = new JavaScriptSerializer();
dynamic config = js.Deserialize<dynamic>(jsonString);

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
     HttpCookie LandingUrl = new HttpCookie("LandingUrl", "; path=/; expires=Thu, 01-Jan-70 00:00:01 GMT;");
     Response.Cookies.Add(LandingUrl);
     LandingUrl = new HttpCookie("LandingUrl", HttpContext.Current.Request.Url.Scheme+"://"+ HttpContext.Current.Request.Url.Authority + "/SVAuth/adapters/aspx/AllInOne.aspx; path=/; ");
     Response.Cookies.Add(LandingUrl);
}
string req = config["AgentSettings"]["scheme"] + "://" + config["AgentSettings"]["agentHostname"] + ":" + config["AgentSettings"]["port"];
req += "/login/" + Request.QueryString["provider"] + "?conckey=" + conckey ;
req += "&concdst=" + config["WebAppSettings"]["scheme"] + "://" + config["WebAppSettings"]["hostname"] + ":" + config["WebAppSettings"]["port"] + "?" + config["WebAppSettings"]["platform"]["name"];

Response.Redirect(req);
%>

 