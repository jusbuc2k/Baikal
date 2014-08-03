<?php

namespace Baikal\Core;

/**
 * This is an authentication backend that is designed to use 
 * authenticate a user with an application password created 
 * using the RoundCube plugin here:
 * https://github.com/jusbuc2k/roundcube-application_passwords/
 */
class RcubeAppPasswordsAuth extends \Sabre\DAV\Auth\Backend\AbstractBasic {

    /**
     * Reference to PDO connection
     *
     * @var PDO
     */
    protected $pdo;

    /**
     * PDO table name we'll be using
     *
     * @var string
     */
    protected $tableName;

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
    public function __construct(\PDO $pdo, $authRealm, $tableName = 'users') {

        $this->pdo = $pdo;
        $this->tableName = $tableName;
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
		$service = 'CardDAV';
		$remoteAddr = $_SERVER['REMOTE_ADDR'];
		$format = 'default';
		$ignoreSpace = 1;
		
		// user, password, service name, remote ip, out format, ignore whitespace
        $stmt = $this->pdo->prepare('CALL roundcube.app_authenticate(?, ?, ?, ?, ?, ?);');		
        $stmt->execute(array($username,$password,$service,$remoteAddr,$format,$ignoreSpace));
        $result = $stmt->fetchAll();

        if (count($result)) {
			$this->currentUser = $username;
			return true;
		}
		
        return false;
    }

}
