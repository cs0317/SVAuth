<?php
class OIDCAuth {

/* URL setting */
	private static $login_url="https://localhost:3000/login/MicrosoftAzureAD";
    private static $logout_url="http://localhost/SVAuth/adapters/php/sign_out.php";
/* ******************** */

	private static function init() {
		global $wgSessionName;
		global $wgSessionsInMemcached;
 		global $wgSessionsInObjectCache;
		if ( ( !isset( $wgSessionName ) || !$wgSessionName )
 			&& ( !isset( $wgSessionsInObjectCache ) || !$wgSessionsInObjectCache )
 			&& ( !isset( $wgSessionsInMemcached ) || !$wgSessionsInMemcached )
 		) {
 			$wgSessionName = ini_get( 'session.name' );
 		}
		return true;
	}
	public static function hookGetPreferences( $user, &$preferences ) {
		unset( $preferences['password'] );
		unset( $preferences['rememberpassword'] );
		unset( $preferences['realname'] );
		unset( $preferences['emailaddress'] );
		return true;
	}
	public static function hookSpecialPage_initList( &$pages ) {
		unset( $pages['ChangePassword'] );
		unset( $pages['PasswordReset'] );
		unset( $pages['ConfirmEmail'] );
		unset( $pages['ChangeEmail'] );
		return true;
	}
	public static function hookLoginForm( &$template ) {
		if ( empty($_SESSION['UserID'])) {
			header("Location: " . self::$login_url, true, 303);
		}
		return true;
	}
	public static function hookUserLogout() {
		if (!empty($_SESSION['UserID'])) {
			header("Location: " . self::$logout_url, true, 303);
		}
		return true;
	}
	public static function hookLoadSession( $user, &$result ) {
		if ( $result ) {
			return true;
		}
		if ( !empty($_SESSION['UserID'])) {
			self::loadUser( $user );
			if ( $wgBlockDisablesLogin && $user->isBlocked() ) {
				$block = $user->getBlock();
				throw new UserBlockedError( $block );
			} else {
				$result = true;
				if ( session_id() == '' ) {
					wfSetupSession();
				}
				return true;
			}
		}
		// Not authenticated, but no errors either
		// Return means success, $result is still false
		return true;
	}
	public static function hookPersonalUrls( array &$personal_urls, Title $title ) {
		if ( empty($_SESSION["UserID"])) {
		    if ( isset( $personal_urls['login'] ) ) {
			$personal_urls['login']['href'] = self::$login_url;
		    }
		    if ( isset( $personal_urls['anonlogin'] ) ) {
 			$personal_urls['anonlogin']['href'] = self::$login_url;
		    }
		} else {
		    if ( isset( $personal_urls['logout'] ) ) {
			$personal_urls['logout']['href'] = self::$logout_url;
		    }
		}
		return true;
	}
	public static function hookMediaWikiPerformAction( $output, $article, $title, $user, $req, $w ) {
		self::init();
		return true;
	}
        protected static function loadUser( User $user) {
                $username = ucfirst($_SESSION['email']);
                $id = User::idFromName( $username );
                if ( $id ) {
                        $user->setId( $id );
                        $user->loadFromId();
                } else {
                        $user->setName( $username );
                }
                self::updateUser( $user);
        }

        protected static function updateUser( User $user ) {
                $changed = false;
                if ( $user->getRealName() !==  $_SESSION['FullName']) {
                        $changed = true;
                        $user->setRealName( $_SESSION['FullName'] );
                }
                if ( $user->getEmail() !== $_SESSION['email'] ) {
                        $changed = true;
                        $user->setEmail( $_SESSION['email'] );
                        $user->ConfirmEmail();
                }
                if ( !$user->getId() ) {
                        $user->setName( ucfirst($_SESSION['email']) );
                        $user->setInternalPassword( null ); // prevent manual login u$
                        $user->addToDatabase();
                } elseif ( $changed ) {
                        $user->saveSettings();
                }
        }
}

