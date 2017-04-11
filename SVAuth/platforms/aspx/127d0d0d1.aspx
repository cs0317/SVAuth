<script>
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<% 
  if (Session["UserID"]!=null && Session["UserID"]!="") {
       Response.Write("top.location.href=\"AllInOne.aspx\";");
  }
%>
</script>

 