<?php
if ( !defined( 'MEDIAWIKI' ) ) {
	die( "This is a MediaWiki extension, and must be run from within MediaWiki.\n" );
}
$GLOBALS['wgAutoloadClasses']['OIDCAuth'] =
	__DIR__ . DIRECTORY_SEPARATOR . 'OIDCAuth.class.php';
$GLOBALS['wgHooks']['UserLoadFromSession'][] = 'OIDCAuth::hookLoadSession';
$GLOBALS['wgHooks']['GetPreferences'][] = 'OIDCAuth::hookGetPreferences';
$GLOBALS['wgHooks']['SpecialPage_initList'][] = 'OIDCAuth::hookSpecialPage_initList';
$GLOBALS['wgHooks']['UserLoginForm'][] = 'OIDCAuth::hookLoginForm';
$GLOBALS['wgHooks']['UserLogoutComplete'][] = 'OIDCAuth::hookUserLogout';
$GLOBALS['wgHooks']['PersonalUrls'][] = 'OIDCAuth::hookPersonalUrls';
$GLOBALS['wgHooks']['MediaWikiPerformAction'][] = 'OIDCAuth::hookMediaWikiPerformAction';
$wgGroupPermissions['*']['createaccount'] = false;

session_start();
