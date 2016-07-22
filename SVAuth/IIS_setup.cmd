cd %~dp0
%systemroot%\system32\inetsrv\AppCmd.exe ADD vdir /app.name:"Default Web Site/" /path:/SVAuth/ /physicalPath:%cd%
