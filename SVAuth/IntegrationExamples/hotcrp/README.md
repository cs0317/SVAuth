# HotCRP integration

Assuming a working installation of HotCRP is running at `http://localhost:8080`.
The source tree directory is at `hotcrp` folder.

## HotCRP docker image
HotCRP docker file is included. To build and run the image:

```
docker-compose build
docker-compose up -d
docker-compose ps
```

The HotCRP should be running and listen on port `8080`

## HotCRP configuration

hotcrp/lib/login.php

```php
    static function authjs_login($email){
        global $Conf, $Me;
        if (($user = self::authjs_login_helper($email))){
            $_SESSION["trueuser"] = (object) array("email" => $user->email);
            $Conf->save_session("freshlogin", true);
            $Me = $user->activate();
        }
    }

    static function authjs_login_helper($email){
        $user = Contact::find_by_email($email);
        if (!$user){
            $reg = Contact::safe_registration(array(
                "email" => $email
            ));
            $reg->no_validate_email = true;
            if (($user = Contact::create($reg))){
                return $user;
            }
        }
        return $user;
    }
```

hotcrp/SVAuth/platforms/php/CreateNewSession.php

```php
<?php
require_once("../../../src/initweb.php");

$UserID = $_POST['UserID'];
$email = $_POST['Email'];

if ((strlen($UserID) == 0)) {
    LoginHelper::logout(true);
}
else {
    LoginHelper::authjs_login($email);
}
?>
```


## svAuth configuration

svAuth/config.json
```
webappsetting.port = 8080
```

svAuth/common/util.cs
```
// handle cookie for “hotcrp”
abandonSessionRequest.Headers.Add("Cookie",
    "ASP.NET_SessionId="+context.http.Request.Cookies["ASP.NET_SessionId"]  
        + ";" +
    "PHPSESSID=" + context.http.Request.Cookies["PHPSESSID"]
                        + ";" +
    "hotcrp=" + context.http.Request.Cookies["hotcrp"]
    );
```
