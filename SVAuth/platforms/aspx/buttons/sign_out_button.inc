<!-- logout button -->
<%if (Session["UserID"]!=null) { %>
  <script runat="server">
  void clearSession(object sender, System.EventArgs e)
  {
    Session.Abandon();
    Response.Redirect(Request.RawUrl);
  }
  </script>
  <form runat="server">
     <asp:ImageButton runat="server" OnClick="clearSession
" ImageUrl="/Auth.JS/images/Sign_out.jpg" width=40 height=40 oncontextmenu="copyToClipboard('\<!-- #include virtual =&#34;','\\buttons\\sign_out_button.inc\&#34; --\>');return false;"/>
  </form>
<% } %>
<!-- end of logout button -->