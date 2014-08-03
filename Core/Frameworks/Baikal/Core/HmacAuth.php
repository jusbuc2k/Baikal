<?php

namespace Baikal\Core;

/**
 * This authentication backend validates the username/password combination
 * assuming the password field is ah hmac sha256 hash.
 * 
 * This method is for providing CardDAV to the RoundCube mail client using the
 * a CardDAV plugin that has been configured to send an hmac hash instead
 * of a password. The hash key is a shared secret between the Baikal and RoundCube
 * which allows the user to access the CardDAV server from Roundcube without 
 * having to enter their password. 
 * 
 * Note: If you are using a CardDAV plugin for RoundCube that allows the user
 * to enter their own URL, you probably shouldn't use this, since they could
 * enter anyone else's URL to access their address books.
 * 
 */
class HmacAuth extends \Sabre\DAV\Auth\Backend\AbstractBasic {

    /**
     * Reference to PDO connection
     *
     * @var PDO
     */
    protected $pdo;

    /**
     * Authentication realm
     *
     * @var string
     */
    protected $authRealm;

    /**
     * Creates the backend object.
     *
     * If the filename argument is passed in, it will parse out the specified file fist.
     *
     * @param PDO $pdo
     * @param string $tableName The PDO table name to use
     */
    public function __construct(\PDO $pdo, $authRealm) {

        $this->pdo = $pdo;        
        $this->authRealm = $authRealm;
    }
	
    /**
     * Validates a username and password
     *
     * This method should return true or false depending on if login
     * succeeded.
     *
     * @param string $username
     * @param string $password
     * @return bool
     */
    public function validateUserPass($username, $password) {
		if (!defined("BAIKAL_DAV_AUTH_HMAC_SECRET")){
			return false;
		}
		$secret = BAIKAL_DAV_AUTH_HMAC_SECRET;		
		$now = time();
		$salt = gmdate('YmdH', $now);
		$altSalt = gmdate('YmdH', $now + (60 * 5));
		
		if (gmdate('YmdH', $now) != gmdate('YmdH', $now + (60 * 5))) {
			$altSalt = date('YmdH', $now - (60 * 5));
		}
		
		$hash = hash_hmac('sha256', $username.$salt, $secret, false);
		$altHash = hash_hmac('sha256', $username.$altSalt, $secret, false);
				
		if ($this->hash_compare($hash, $password) || $this->hash_compare($altHash, $password)) {
			$this->currentUser = $username;
			return true;
		}
				
        return false;
    }
	
	protected function hash_compare($a, $b) {
        if (!is_string($a) || !is_string($b)) {
            return false;
        }
       
        $len = strlen($a);
        if ($len !== strlen($b)) {
            return false;
        }

        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            $status |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $status === 0;
    }

}
