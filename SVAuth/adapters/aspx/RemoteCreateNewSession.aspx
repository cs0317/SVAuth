<%@ Page Language="C#" %>
<%@ Import Namespace= "System.Security.Cryptography" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>
<%@ Import Namespace= "System.Text" %>
<%@ Import Namespace= "System.IO" %>
<%@ Import Namespace= "System.Web.SessionState" %>
<%@ Import Namespace= "System.Net" %>

<%
var jsonString = File.ReadAllText(Request.PhysicalPath+"/../../adapter_config/adapter_config.json");
JavaScriptSerializer js = new JavaScriptSerializer();
dynamic config = js.Deserialize<dynamic>(jsonString);

var session_id=System.Web.HttpContext.Current.Session.SessionID;
Response.Write( "session_id=" + session_id +"<br>");
Response.Write( "session[UserID]=" + Session["UserID"] +"<br>");
if (String.IsNullOrEmpty(Request.QueryString["pass"]) || Request.QueryString["pass"]!="second") {
   SessionIDManager manager = new SessionIDManager();
   string newSessionId =  manager.CreateSessionID(HttpContext.Current);
   bool redirected = false;
   bool isAdded = false;
   manager.SaveSessionID(HttpContext.Current, newSessionId, out redirected, out isAdded);
   string redir = HttpContext.Current.Request.Url + "&pass=second&old_session_id="+session_id;
   Response.Redirect(redir);
}

var reqstr=config["AgentSettings"]["scheme"]+"://"+config["AgentSettings"]["agentHostname"]+":"
                            +config["AgentSettings"]["port"]+"/CheckAuthCode?authcode="+Request.QueryString["authcode"];
Response.Write("<br>reqstr=" + reqstr);

HttpWebRequest request = (HttpWebRequest) WebRequest.Create(reqstr);
ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.SystemDefault |
             SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
HttpWebResponse response = (HttpWebResponse) request.GetResponse();

if (response.StatusCode != HttpStatusCode.OK)        
     throw new Exception("bad response!");
var reader = new StreamReader(response.GetResponseStream());
var respText = reader.ReadToEnd();
Response.Write("<br>respText1=" + respText);
dynamic entry = js.Deserialize<dynamic>(respText);
var conc = entry["userProfile"];

string old_session_id = Request.QueryString["old_session_id"];
HashAlgorithm hashAlgo = SHA256.Create();
byte[] conckey_bytes=hashAlgo.ComputeHash(System.Text.Encoding.UTF8.GetBytes(old_session_id));
string conckey = BitConverter.ToString(conckey_bytes).Replace("-","");
Response.Write("<br>conckey=" + conckey);

if (conckey!=entry["conckey"] || conckey!=Request.QueryString["conckey"])
    throw new Exception("conckey mismatch!");
var concdst= config["WebAppSettings"]["scheme"] + "://" + config["WebAppSettings"]["hostname"] + ":" + config["WebAppSettings"]["port"] 
             + "?" + config["WebAppSettings"]["platform"]["name"];
Response.Write("<br>concdst=" + concdst);
if (concdst!=entry["concdst"])
    throw new Exception("concdst mismatch!");

Session["SVAuth_Email"] = conc["Email"];
Session["SVAuth_UserID"] = conc["UserID"];
Session["SVAuth_FullName"] = conc["FullName"];
Session["SVAuth_Authority"]= conc["Authority"]; 
Response.Write("<br>session id=" + System.Web.HttpContext.Current.Session.SessionID);
Response.Write( "LandingUrl=" + Request.Cookies["LandingUrl"].Value +"<br>");
Response.Redirect(Request.Cookies["LandingUrl"].Value);
%>
