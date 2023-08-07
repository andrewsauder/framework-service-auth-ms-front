<?php


namespace gcgov\framework\services\authmsfront\controllers;


use gcgov\framework\exceptions\controllerException;
use gcgov\framework\exceptions\modelException;
use gcgov\framework\interfaces\controller;
use gcgov\framework\models\controllerDataResponse;


class auth implements controller {

	public function __construct() {

	}

	//URL: /.well-known/jwks.json
	public function jwks() : controllerDataResponse {
		$jwtService = new \gcgov\framework\services\jwtAuth\jwtAuth();
		$jwksKeys = $jwtService->getJwksKeys();

		$data = [
			'keys' => $jwksKeys
		];

		return new controllerDataResponse($data);
	}


	/**
	 * @return \gcgov\framework\models\controllerDataResponse
	 * @throws \gcgov\framework\exceptions\controllerException
	 */
	public function microsoft() : controllerDataResponse {

		if( !isset( $_SERVER[ 'HTTP_AUTHORIZATION' ] ) ) {
			new controllerException( 'Microsoft access token not provided in authorization header', 401 );
		}

		//authenticate user with Microsoft
		$microsoftAuthService = new \gcgov\framework\services\microsoft\auth();
		$tokenInfo = $microsoftAuthService->verify();
		$user = $this->lookupUserMicrosoftTokenInfo( $tokenInfo );

		//convert \app\models\user to authUser singleton
		$authUser = \gcgov\framework\services\request::getAuthUser();
		$authUser->setFromUser( $user );

		//generate our custom jwt and return it to the user
		$jwtService  = new \gcgov\framework\services\jwtAuth\jwtAuth();
		$accessToken = $jwtService->createAccessToken( $authUser );

		//return data
		$data = [
			'accessToken' => $accessToken->toString()
		];

		return new controllerDataResponse($data);

	}


	/**
	 * Processed after lifecycle is complete with this instance
	 */
	public static function _after() : void {

	}


	/**
	 * Processed prior to __constructor() being called
	 */
	public static function _before() : void {

	}


	/**
	 * @throws \gcgov\framework\exceptions\controllerException
	 */
	private function lookupUserMicrosoftTokenInfo( \gcgov\framework\services\microsoft\components\tokenInfomation $tokenInfo ): \gcgov\framework\services\mongodb\models\auth\user {
		$userClassName = \gcgov\framework\services\request::getUserClassFqdn();

		//get user from database using Microsoft unique Id
		try {
			return $userClassName::getOneByExternalId( $tokenInfo->oid );
		}
		catch( modelException $e ) {
			//user not found in the database by unique id
			if( !isset( $tokenInfo->preferred_username ) ) {
				throw new \gcgov\framework\exceptions\controllerException( 'The Microsoft user may need to be added to the user collection within the application. This Microsoft user could not be found in the app user list by external id and does not have a preferred username to lookup by email.', 404, $e );
			}
		}

		//look up if they are a new user that just has an email address
		try {
			$user = $userClassName::getOneByEmail( $tokenInfo->preferred_username );
		}
		catch( modelException $e ) {
			throw new \gcgov\framework\exceptions\controllerException( 'The Microsoft user may need to be added to the user collection within the application. This Microsoft user could not be found in the app user list by external id or email address.', 404, $e );
		}

		//set the external id for future logins
		$user->externalId = $tokenInfo->oid;
		try {
			$updateResult = $userClassName::save( $user );
		}
		catch( modelException $e ) {
			//failed to save external id - no problem, we will try again next sign in
		}

		return $user;
	}

}
