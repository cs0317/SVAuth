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

hotcrp/pages/home.php
Add a link to use SVAuth public agent
```php
<a href='http://authjs.westus.cloudapp.azure.com:8000/SVAuth/adapters/php/start.php?provider=CILogon'><img src='http://www.cilogon.org/_/rsrc/1304392039391/config/cilogon-logon-48-g.png' width='16%' height='16%'/></a>
```


hotcrp/SVAuth/adapters/php/RemoteCreateNewSession.php

```php
...

$UserID = $conc['UserID'];
$FullName = $conc['FullName'];
$email = $conc['Email'];

echo $UserID;

if ((strlen($UserID) == 0)) {
    file_put_contents($file, sprintf("recvd empty request, destroying session \n"), FILE_APPEND);
    file_put_contents($file, sprintf("cookie %s \n", $_COOKIE['hotcrp']), FILE_APPEND);
    LoginHelper::logout(true);
}
else {
    file_put_contents($file, sprintf("recvd login request for %s \n", $UserID), FILE_APPEND);
    file_put_contents($file, sprintf("cookie %s \n", $_COOKIE['hotcrp']), FILE_APPEND);
    LoginHelper::authjs_login($email);
}

header ("location:" . "http://authjs.westus.cloudapp.azure.com:8000");
```


### Copy hotcrp source tree to /opt

```
cp -r hotcrp /opt
```

## Configure svAuth

adapter_config.json

```
{
  "WebAppSettings": {
    "hostname": "authjs.westus.cloudapp.azure.com",
    "scheme": "http",
    "port": "8000",
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
