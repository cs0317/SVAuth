<?php session_start(); ?> 
<?php
if (!(strlen($_SESSION['UserID'])>0)) { ?>
  
   <script>
     function MicrosoftAzureAD_login() {

     var reg = new RegExp( '[?&]' + 'ReturnPort' + '=([^&#]*)', 'i' );
     var ReturnPort=reg.exec(window.location.href);
     ReturnPort = ReturnPort? ReturnPort[1]:null

     if (  ReturnPort==null || ReturnPort=="" || ReturnPort=="null" )
     ReturnPort="3000";

     var reg1 = new RegExp( '[?&]' + 'scheme' + '=([^&#]*)', 'i' );
     var scheme=reg1.exec(window.location.href);
     scheme = scheme? scheme[1]:null

     if (  scheme==null || scheme=="" || scheme=="null" )
     ReturnPort="https";

     document.cookie="LoginPageUrl=; expires=Thu, 01-Jan-70 00:00:01 GMT;";
     document.cookie="LoginPageUrl="+location+";path=/";
     window.location=(scheme+"://"+location.host+":"+ReturnPort+"/login/MicrosoftAzureAD");
     }
   </script>

    <img OnClick="MicrosoftAzureAD_login();" src="/SVAuth/images/MicrosoftAzureAD_login.jpg" width=100 height=40 oncontextmenu="copyToClipboard('&lt;?php include dirname($_SERVER[&#34;PATH_TRANSLATED&#34;]).&#34;\\buttons\\MicrosoftAzureAD_login_button.inc&#34; ?&gt;');return false;"/>
<?php } ?>