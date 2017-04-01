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
var jsonString = File.ReadAllText(Request.PhysicalPath+"/../../resources/config.json");
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

		  document.cookie="LoginPageUrl=; path=/; expires=Thu, 01-Jan-70 00:00:01 GMT;";
		  document.cookie="LoginPageUrl="+location+";path=/";
		  url=scheme+"://"+location.host+":"+port+
		      <% if (String.Compare(config["AgentSettings"]["agentScope"],"local")==0) {
	                  Response.Write("\"/login/\"+provider;");
					} else {  
					   Response.Write("\"/SVAuth/platforms/php/start.php?provider=\"+provider;");
					}
			  %>	 
		  window.location=url;
	  }
      function clearSession() {
	        var xhttp = new XMLHttpRequest();
	        xhttp.onreadystatechange = function() {
                if (xhttp.readyState == 4) {
	              location.reload();
                }
            };
            xhttp.open("GET", "sign_out.aspx", true);
            xhttp.send();
         }
</script>


<div id="grad1">
<% string[] providers = new string[] {"Facebook", "Microsoft", "MicrosoftAzureAD", "Google", "Yahoo"};  
   if (Session["UserID"]!=null) { 
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

<h3>User identity bound to this session:<br /></h3>

<font face="Courier New" size=2>
 Session["UserID"]=<%:Session["UserID"]%> <br />
 Session["FullName"]=<%:Session["fullname"]%> <br />
 Session["email"]=<%:Session["email"]%> <br />
</font>
<br />

</body>
</html>
