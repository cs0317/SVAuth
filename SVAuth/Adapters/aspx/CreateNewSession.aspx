<%@ Page Language="C#" %>

<script runat="server">
protected void Page_Load(object sender, EventArgs e)  {

 string remoteAddr = Request.ServerVariables["REMOTE_ADDR"];
 // I was getting ::1 when using a hostname of localhost. ~ t-mattmc@microsoft.com 2016-06-01
 if (remoteAddr != "127.0.0.1" && remoteAddr != "::1") {
    Response.StatusCode = 403;
    Response.ContentType = "text/plain";
 } else {
   if (String.IsNullOrEmpty(Request.Form["UserID"])) {
      Session.Abandon();
      Response.Write("Session abadoned.");
      Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", ""));

   } else {
    Session["SVAuth_UserID"]="Request.Form[UserID]";
    Session["SVAuth_Fullname"]=Request.Form["Fullname"];
    Session["SVAuth_Email"]=Request.Form["Email"];
    Session["SVAuth_Authority"]=Request.Form["Authority"]; 
    Response.Write("Session variables are set.");
   }    
 }
}
</script>

