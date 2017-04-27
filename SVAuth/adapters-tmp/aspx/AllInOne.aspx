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

<%@ Page Language="C#" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace= "System.Security.Cryptography" %>
<% 
var jsonString = File.ReadAllText(Request.PhysicalPath+"/../../adapter_config/adapter_config.json");
JavaScriptSerializer js = new JavaScriptSerializer();
dynamic config = js.Deserialize<dynamic>(jsonString);

string scheme, port;
if (String.Compare(config["AgentSettings"]["agentScope"],"local")==0) {
	scheme = config["AgentSettings"]["scheme"];
    port=config["AgentSettings"]["port"];
} else {
	scheme = config["WebAppSettings"]["scheme"];
    port=config["WebAppSettings"]["port"];
}
%>

<body>
 <script>
      function login_start(provider) {
          scheme = "<% Response.Write(scheme); %>";
		  port = "<% Response.Write(port); %>";

		  document.cookie="LandingUrl=; path=/; expires=Thu, 01-Jan-70 00:00:01 GMT;";
		  document.cookie="LandingUrl="+location+";path=/";
          hostname = location.host;
		  if (provider.toLowerCase() === "Weibo".toLowerCase() && hostname=="localhost") {
                     hostname="127.0.0.1";
		   }
		  url=scheme+"://"+hostname+":"+port+
		      <% if (String.Compare(config["AgentSettings"]["agentScope"],"local")==0) {
	                  Response.Write("\"/login/\"+provider;");
					} else {  
					   Response.Write("\"/SVAuth/adapters/aspx/start.aspx?provider=\"+provider;");
					}
			  %>	 
		  window.location=url;
	  }
      function clearSession() {
	        var xhttp = new XMLHttpRequest();
	        xhttp.onreadystatechange = function() {
                if (xhttp.readyState == 4) {
                <%  
				if (HttpContext.Current.Request.Url.Host=="127.0.0.1") { 
				    Response.Write( "location.href=\"" + HttpContext.Current.Request.Url.Scheme + "://localhost:" + HttpContext.Current.Request.Url.Port + "/SVAuth/adapters/aspx/AllInOne.aspx\";"); 
                 } else  {
	                Response.Write("location.reload();");
				}
			    %>
	            }
            };
            xhttp.open("GET", "sign_out.aspx", true);
            xhttp.send();
         }
</script>


<div id="grad1">
<% string[] providers = new string[] {"Facebook", "Microsoft", "MicrosoftAzureAD", "Google", "Yahoo", "Weibo"};  
   if (Session["SVAuth_UserID"]!=null) { 
%>
    <img OnClick="clearSession();" src="../resources/images/Sign_out.jpg" width=40 height=40>
<% } else { 
   foreach (string provider in providers) {
       Response.Write( "<img OnClick=\"login_start('" + 
	           provider + 
		    "');\" src=\"../resources/images/" +
			   provider + 
			"_login.jpg\" width=100 height=40>");
     }
   }
%>
</div>

<h3>User identity bound to this session (<%:System.Web.HttpContext.Current.Session.SessionID%>):<br /></h3>

<font face="Courier New" size=2>
 Session["SVAuth_UserID"]=<%:Session["SVAuth_UserID"]%> <br />
 Session["SVAuth_FullName"]=<%:Session["SVAuth_FullName"]%> <br />
 Session["SVAuth_Email"]=<%:Session["SVAuth_Email"]%> <br />
 Session["SVAuth_Authority"]=<%:Session["SVAuth_Authority"]%> <br />
</font>
<br />

<%  
   /* because weibo doesn't allow localhost to be the redirect_uri */
   if (HttpContext.Current.Request.Url.Host=="localhost") {  
      Response.Write("<iframe style=\"display: none;\" src=\""
	        + config["WebAppSettings"]["scheme"]
			+ "://127.0.0.1:" 
	        + config["WebAppSettings"]["port"]
			+ "/SVAuth/adapters/aspx/127d0d0d1.aspx\""
	        + "></iframe>");
   } 
%> 
</body>
</html>
