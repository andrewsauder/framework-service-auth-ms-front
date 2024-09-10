<?php

namespace gcgov\framework\services\authmsfront;

class msAuthConfig {

	private bool $blockNewUsers = true;

	/** @var string[] $defaultNewUserRoles  */
	private array $defaultNewUserRoles = [];

	private static msAuthConfig $instance;


	private function __construct() {
	}


	/**
	 * @return $this
	 */
	final public static function getInstance(): static {
		$calledClass = get_called_class();

		if( !isset( self::$instance ) ) {
			self::$instance = new $calledClass();
		}

		return self::$instance;
	}


	/**
	 * Avoid clone instance
	 */
	final public function __clone() {
	}


	/**
	 * Avoid serialize instance
	 */
	final public function __sleep() {
	}


	/**
	 * Avoid unserialize instance
	 */
	final public function __wakeup() {
	}


	public function isBlockNewUsers(): bool {
		return $this->blockNewUsers;
	}


	/**
	 * @param bool  $blockNewUsers
	 * @param string[] $defaultNewUserRoles
	 *
	 * @return void
	 */
	public function setBlockNewUsers( bool $blockNewUsers, array $defaultNewUserRoles=[] ): void {
		$this->blockNewUsers = $blockNewUsers;
		if(!$this->blockNewUsers) {
			$this->defaultNewUserRoles = $defaultNewUserRoles;
		}
	}


	public function getDefaultNewUserRoles(): array {
		return $this->defaultNewUserRoles;
	}

}
