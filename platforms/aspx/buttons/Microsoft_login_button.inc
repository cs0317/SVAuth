<%--  Facebook login button --%>
<%if (Session["UserID"]==null) { %>
  
   <script>
      function Microsoft_login() {

		  var reg = new RegExp( '[?&]' + 'ReturnPort' + '=([^&#]*)', 'i' );
		  var ReturnPort=reg.exec(window.location.href);
		  ReturnPort = ReturnPort? ReturnPort[1]:null

          if (  ReturnPort==null || ReturnPort=="" || ReturnPort=="null" )
               ReturnPort="3000";

		  document.cookie="LoginPageUrl=; expires=Thu, 01-Jan-70 00:00:01 GMT;";
		  document.cookie="LoginPageUrl="+location+";path=/";
          window.location=("https://"+location.host+":"+ReturnPort+"/login/Microsoft");	
	  }
    </script>

    <img OnClick="Microsoft_login();" src="/Auth.JS/images/Microsoft_login.jpg" width=100 height=40 oncontextmenu="copyToClipboard('\<!-- #include virtual =&#34;','\\buttons\\Microsoft_login_button.inc\&#34; --\>');return false;"/>
<% } %>

<%--  end of Facebook login button --%>