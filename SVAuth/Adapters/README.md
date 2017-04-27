# How to use SVAuth on your website

## Set up

Suppose your website http(s)://foo.com (note: "foo.com" can be "localhost") is running PHP. Here is how you use SVAuth:

* Create a directory or a virtual directory on foo.com called ```/SVAuth```;
* Unzip the zip file of the "SVAuth-adapter" zip file into a folder;
* Open ```adapter_config/adapter_config.json```. You will see the following:
```
{
  "WebAppSettings": {
    "hostname": "localhost",
    "scheme": "http",
    "port": "80",
    "platform": {
      "name": "php"
    }
  },

  "AgentSettings": {
    "scheme": "https",
    "port": "3020",
    "agentScope": "*",
    "agentHostname": "authjs.westus.cloudapp.azure.com"
  }
}
```
* Modify the ```WebAppSettings``` section to match your website platform;
* Copy the ```adapters``` folder into the ```/SVAuth``` directory on your website;
* Visit http(s)://foo.com/SVAuth/adapters/php/AllInOne.php, you should see [**a page like this**](http://authjs.westus.cloudapp.azure.com/SVAuth/adapters/php/AllInOne.php), and should be able to click on the buttons to sign in.

## Integrate with your web application

* If your PHP page ```x.php``` wants to initiate a ```Facebook``` login, it simply redirects the browser to http(s)://foo.com/SVAuth/adapters/php/start.php?provider=```Facebook```;
* SVAuth will set the user data into the following session variables in your session. Your application code takes the data from there. That's it.
```
Session["SVAuth_UserID"]=436436434635643 
Session["SVAuth_FullName"]=John Doe 
Session["SVAuth_Email"]=johndoe@abcd.com 
Session["SVAuth_Authority"]=Facebook.com 
```

#### Other web languages and SSO services
In this README description, "php" can be replaced by the following:
```php```,```aspx```. 

"Facebook" can be replaced by ```Facebook```, ```Microsoft```, ```MicrosoftAzureAD```, ```Google```, ```Yahoo```, ```LinkedIn```, ```Weibo```.

#### Customize the landing URL

By default, SVAuth will redirect the browser back to ```x.php``` when the login is done. If you want the user to land on a different page ```y.php```, ```x.php``` should set the "LandingUrl" cookie to be the full URL of ```y.php```. This can be implemented in PHP as follows:
```
setcookie("LandingUrl", "http(s)://foo.com/y.php", 0 ,"/"); 
```