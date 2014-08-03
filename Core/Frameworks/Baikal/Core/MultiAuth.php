<?php

namespace Baikal\Core;

/**
 * This authentication backend just calls other backends specified by 
 * the $providers constructor parameter, which is an array of provider names.
 */
class MultiAuth extends \Sabre\DAV\Auth\Backend\AbstractBasic {

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
     * The list of authentication provider names to try
     *
     * @var array
     */
	protected $providers;

    /**
     * Creates the backend object.
     *
     * If the filename argument is passed in, it will parse out the specified file fist.
     *
     */
    public function __construct(\PDO $pdo, $authRealm, $providers) {

        $this->pdo = $pdo;
        $this->authRealm = $authRealm;
		$this->providers = is_array($providers) ? $providers : explode(',', $providers);
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
		foreach ($this->providers as $provider) {
			$className = "\\Baikal\\Core\\".$provider."Auth";
			$auth = new $className($this->pdo, $this->authRealm);
			if ($auth->validateUserPass($username,$password)){
				return true;
			}
		}	
        return false;
    }	
}
