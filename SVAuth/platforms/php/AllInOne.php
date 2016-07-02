<html>

<head>

<style>
#grad1 {
    background: blue; /* For browsers that do not support gradients */    
    background: -webkit-linear-gradient(left, blue , green); /* For Safari 5.1 to 6.0 */
    background: -o-linear-gradient(right, blue, green); /* For Opera 11.1 to 12.0 */
    background: -moz-linear-gradient(right, blue, green); /* For Firefox 3.6 to 15 */
    background: linear-gradient(to right, blue , green); /* Standard syntax (must be last) */
}
</style>
</head>


<body>


<script>
 function copyToClipboard(str1) {
    window.prompt("This is the code of the button.\nCopy to clipboard: Ctrl+C, Enter.\n", str1);
  }
</script>

<div id="grad1">
<?php include dirname($_SERVER['PATH_TRANSLATED'])."\buttons\sign_out_button.inc" ?>
<?php include dirname($_SERVER["PATH_TRANSLATED"])."\buttons\Facebook_login_button.inc" ?>
<?php include dirname($_SERVER['PATH_TRANSLATED'])."\buttons\Microsoft_login_button.inc" ?>
<?php include dirname($_SERVER['PATH_TRANSLATED'])."\buttons\Google_login_button.inc" ?>
</div>

<h3>First, test this page:<br /></h3>

1. Click any button (login or logout) on the banner above; <br />
2. See the current session variable values: <br />


<font face="Courier New" size=2>
 Session["UserID"]=<?php echo $_SESSION['UserID']; ?> <br />
 Session["FullName"]=<?php echo $_SESSION['FullName']; ?> <br />
 Session["email"]=<?php echo $_SESSION['email']; ?> <br />
</font>
<br />


<h3>Next, follow the instruction to paste code into any PHP page of your app: <br /></h3>

1. The code of every button can be obtained by right-clicking the button. For example, the following are the Facebook login button and a logout button. You can paste them anywhere you want in your page.<br />
<pre>
&lt;?php include dirname($_SERVER["PATH_TRANSLATED"])."\buttons\sign_out_button.inc" ?&gt;
&lt;?php include dirname($_SERVER["PATH_TRANSLATED"])."\buttons\Facebook_login_button.inc" ?&gt;

</pre>
</body>
</html>
