<%if (Session["UserID"]==null) { %>
  
   <script>
      function Yahoo_login() {

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
          window.location=(scheme+"://"+location.host+":"+ReturnPort+"/login/Yahoo");	
	  }
    </script>

    <img OnClick="Yahoo_login();" src="/SVAuth/images/Yahoo_login.jpg" width=100 height=40 oncontextmenu="copyToClipboard('\<!-- #include virtual =&#34;','\\buttons\\Yahoo_login_button.inc\&#34; --\>');return false;"/>
<% } %>

<%--  end of Facebook login button --%>