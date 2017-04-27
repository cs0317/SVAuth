<script>
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<% 
  if (Session["SVAuth_UserID"]!=null && Session["SVAuth_UserID"]!="") {
       Response.Write("top.location.href=\"AllInOne.aspx\";");
  }
%>
</script>

 