# HotCRP integration

# Requirements
A working installation of HotCRP is running at `http://localhost:8000`.
The source tree directory is at `/opt/hotcrp` folder.
SVAuth is running on at `https://localhost:4000`.
Docker and docker-compose are installed.

## HotCRP docker image
HotCRP docker file is included. To build and run the image:

```
docker-compose build
docker-compose up -d
docker-compose ps
```

The HotCRP should be running and listen on port `8000`

## HotCRP configuration

### Clone hotcrp source tree and make following modifications

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
        global $Conf;
        $user = Contact::find_by_email($email);
        if ($user){
            return $user;
        } else {
            $reg = Contact::safe_registration(array(
                "email" => $email
            ));
            $reg->no_validate_email = true;
            if (($user = Contact::create($reg))){
                if ($Conf->setting("setupPhase", false)){
                    $user->save_roles(Contact::ROLE_ADMIN, null);
                    $Conf->save_setting("setupPhase", null);
                }
                return $user;
            }
        }
    }
```

hotcrp/SVAuth/adapters/php/CreateNewSession.php

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

### Copy hotcrp source tree to /opt

```
cp -r hotcrp /opt
```

## Configure svAuth

svAuth/config.json
```
  "__SECTION_1__": "This section configures the web server.",
  "WebAppSettings": {
    "hostname": "TODO: place your fqdn hostname here",
    "scheme": "http",
    "port": "8000",
    "platform": {
      "name": "php",
      "fileExtension": "php"
    }
  },

  "AgentSettings": {
    "scheme": "https",
    "port": "4000"
  },


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

## Run

```
cd svAuth/SVAuth
dotnet run
```
