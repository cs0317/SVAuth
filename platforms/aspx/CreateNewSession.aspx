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

      Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", ""));

   } else {
    Session["UserID"]=Request.Form["UserID"];
    Session["Fullname"]=Request.Form["Fullname"];
    Session["email"]=Request.Form["email"];
    Session["ReturnPort"]=Request.Form["ReturnPort"]; //This is only for debugging in visual studio
   }    
 }
}
</script>

