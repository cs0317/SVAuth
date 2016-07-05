<%--  Facebook login button --%>
<%if (Session["UserID"]==null) { %>
  
   <script>
      function Facebook_login() {

		  var reg = new RegExp( '[?&]' + 'ReturnPort' + '=([^&#]*)', 'i' );
		  var ReturnPort=reg.exec(window.location.href);
		  ReturnPort = ReturnPort? ReturnPort[1]:null

          if (  ReturnPort==null || ReturnPort=="" || ReturnPort=="null" )
               ReturnPort="3000";

		  document.cookie="LoginPageUrl=; expires=Thu, 01-Jan-70 00:00:01 GMT;";
		  document.cookie="LoginPageUrl="+location+";path=/";
          window.location=("http://"+location.host+":"+ReturnPort+"/login/Facebook");	
	  }
    </script>

    <img OnClick="Facebook_login();" src="/SVAuth/images/Facebook_login.png" width=100 height=40 oncontextmenu="copyToClipboard('\<!-- #include virtual =&#34;','\\buttons\\Facebook_login_button.inc\&#34; --\>');return false;"/>
<% } %>

<%--
<script runat="server">
      void Facebook_login(object sender, System.EventArgs e) {
          var ReturnPort="3000";
          if (!String.IsNullOrEmpty(Request.QueryString["ReturnPort"]) && Request.QueryString["ReturnPort"]!="null" )
               ReturnPort=Request.QueryString["ReturnPort"];
		  HttpCookie cookie = new HttpCookie("LoginPageUrl");
		  cookie.Value=Request.Url.ToString();
		  Response.Cookies.Add(cookie);
          Response.Redirect("https://www.facebook.com/v2.0/dialog/oauth?response_type=code&scope=user_about_me%2Cemail&redirect_uri=http%3A%2F%2Fa.local.com%3A"+ReturnPort+"%2Flogin%2FFacebook&client_id=460545824136907");

      }
    </script>
    <form runat="server">
        <asp:ImageButton runat="server" OnClick="Facebook_login
" ImageUrl="/Auth.JS/images/Facebook_login.png" width=100 height=40 oncontextmenu="copyToClipboard('\<!-- #include virtual =&#34;','\\buttons\\Facebook_login_button.inc\&#34; --\>');return false;"/>
    </form>
--%>
<%--  end of Facebook login button --%>