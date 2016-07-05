<?php session_start(); ?> 
<?php
if (!(strlen($_SESSION['UserID'])>0)) { ?>
  
   <script>
      function Microsoft_login() {

		  var reg = new RegExp( '[?&]' + 'ReturnPort' + '=([^&#]*)', 'i' );
		  var ReturnPort=reg.exec(window.location.href);
		  ReturnPort = ReturnPort? ReturnPort[1]:null

          if (  ReturnPort==null || ReturnPort=="" || ReturnPort=="null" )
               ReturnPort="3000";

		  document.cookie="LoginPageUrl=; expires=Thu, 01-Jan-70 00:00:01 GMT;";
		  document.cookie="LoginPageUrl="+location+";path=/";
          window.location=("http://"+location.host+":"+ReturnPort+"/login/Microsoft");	
	  }
    </script>

    <img OnClick="Microsoft_login();" src="/SVAuth/images/Microsoft_login.jpg" width=100 height=40 oncontextmenu="copyToClipboard('&lt;?php include dirname($_SERVER[&#34;PATH_TRANSLATED&#34;]).&#34;\\buttons\\Microsoft_login_button.inc&#34; ?&gt;');return false;"/>
<?php } ?>