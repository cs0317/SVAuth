1. create a folder "OIDCAuth" in the folder /var/www/html/mediawiki/extensions (assuming "/var/www/html/mediawiki" is the installation folder of MediaWiki)

2. Add the following lines in /var/www/html/mediawiki/LocalSettings.php :

#SVAuth
require_once "$IP/extensions/OIDCAuth/OIDCAuth.php";



