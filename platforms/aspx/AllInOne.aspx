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

<%@ Page Language="C#" %>

<script>
  function copyToClipboard(str1,str2) {
    window.prompt("This is the ASP.NET code of the button.\nCopy to clipboard: Ctrl+C, Enter.\n", str1+"<% =System.Configuration.ConfigurationManager.AppSettings["AuthJS_AspxStub_AbsoluteWebRoot"]%>"+str2);
  }
</script>

<div id="grad1">
<!-- #include virtual = "/Auth.JS/platforms/aspx\buttons\sign_out_button.inc" -->
<!-- #include virtual = "/Auth.JS/platforms/aspx\buttons\Facebook_login_button.inc" -->
<!-- #include virtual = "/Auth.JS/platforms/aspx\buttons\Microsoft_login_button.inc" -->
</div>

<h3>First, test this page:<br /></h3>

1. Click any button (login or logout) on the banner above; <br />
2. See the current session variable values: <br />


<font face="Courier New" size=2>
 Session["UserID"]=<%:Session["UserID"]%> <br />
 Session["FullName"]=<%:Session["fullname"]%> <br />
 Session["email"]=<%:Session["email"]%> <br />
</font>
<br />


<h3>Next, follow the instruction to paste code into any ASPX page of your app: <br /></h3>

1. Paste the following code in the beginning of the BODY section of your page;</br>
<pre>
&lt;%@ Page Language="C#" %&gt;
</pre>
2. The code of every button can be obtained by right-clicking the button. For example, the following are the Facebook login button and a logout button. You can paste them anywhere you want in your page.<br />
<pre>
&lt;!-- #include virtual = "/Auth.JS/platforms/aspx\buttons\sign_out_button.inc" --&gt;
&lt;!-- #include virtual = "/Auth.JS/platforms/aspx\buttons\Facebook_login_button.inc" --&gt;
</pre>
</body>
</html>
