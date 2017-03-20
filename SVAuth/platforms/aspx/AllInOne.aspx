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


<body>
 <script>
      function login_start(provider) {

		  var reg = new RegExp( '[?&]' + 'ReturnPort' + '=([^&#]*)', 'i' );
		  var ReturnPort=reg.exec(window.location.href);
		  ReturnPort = ReturnPort? ReturnPort[1]:null

          if (  ReturnPort==null || ReturnPort=="" || ReturnPort=="null" )
               ReturnPort="3000";

          var reg1 = new RegExp( '[?&]' + 'scheme' + '=([^&#]*)', 'i' );
		  var scheme=reg1.exec(window.location.href);
		  scheme = scheme? scheme[1]:null

          if (  scheme==null || scheme=="" || scheme=="null" )
               scheme="https";

		  document.cookie="LoginPageUrl=; expires=Thu, 01-Jan-70 00:00:01 GMT;";
		  document.cookie="LoginPageUrl="+location+";path=/";
          window.location=(scheme+"://"+location.host+":"+ReturnPort+"/login/"+provider);	
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
<%@ Page Language="C#" %>

<div id="grad1">
<%if (Session["UserID"]!=null) { %>
   <img OnClick="clearSession();" src="/SVAuth/platforms/resources/images/Sign_out.jpg" width=40 height=40>
<% } else { %>
   <img OnClick="login_start('Facebook');" src="/SVAuth/platforms/resources/images/Facebook_login.jpg" width=100 height=40>
   <img OnClick="login_start('Microsoft');" src="/SVAuth/platforms/resources/images/Microsoft_login.jpg" width=100 height=40>
   <img OnClick="login_start('MicrosoftAzureAD');" src="/SVAuth/platforms/resources/images/MicrosoftAzureAD_login.jpg" width=100 height=40>
   <img OnClick="login_start('Google');" src="/SVAuth/platforms/resources/images/Google_login.jpg" width=100 height=40>
   <img OnClick="login_start('Yahoo');" src="/SVAuth/platforms/resources/images/Yahoo_login.jpg" width=100 height=40>
<% } %>
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
