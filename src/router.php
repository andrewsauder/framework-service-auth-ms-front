<?php

namespace gcgov\framework\services\authmsfront;

use gcgov\framework\config;
use gcgov\framework\exceptions\serviceException;
use gcgov\framework\models\route;

class router
	implements
	\gcgov\framework\interfaces\router {

	public function getRoutes(): array {
		return [
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/.well-known/jwks.json', '\gcgov\framework\controllers\auth', 'jwks', false ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/auth/microsoft', '\gcgov\framework\controllers\auth', 'microsoft', false ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/auth/fileToken', '\gcgov\framework\controllers\auth', 'fileToken', true )
		];
	}


	public function authentication( \gcgov\framework\models\routeHandler $routeHandler ): bool {
		$authorizationToken = $_SERVER[ 'HTTP_AUTHORIZATION' ] ?? null;

		//ALL other controls must authorization header
		if( !isset( $_SERVER[ 'HTTP_AUTHORIZATION' ] ) ) {
			//is this route allowed to use short lived url tokens?
			if( !$routeHandler->allowShortLivedUrlTokens ) {
				throw new \gcgov\framework\exceptions\routeException( 'Missing Authorization', 401 );
			}

			//get token from url
			if( !isset( $_GET[ 'fileAccessToken' ] ) ) {
				throw new \gcgov\framework\exceptions\routeException( 'Missing Authorization', 401 );
			}
			$authorizationToken = $_GET[ 'fileAccessToken' ];
		}

		//validate JWT provided in request
		$jwtService = new \gcgov\framework\services\jwtAuth\jwtAuth();
		try {
			$parsedToken = $jwtService->validateAccessToken( $authorizationToken );

			//token is valid
			$tokenData   = $parsedToken->claims()->get( 'data' );
			$tokenScopes = (array)$parsedToken->claims()->get( 'scope' );

			//parse the authenticated user from the jwt
			$authUser = \gcgov\framework\services\request::getAuthUser();
			$authUser->setFromJwtToken( $tokenData, $tokenScopes );
		}
		catch( serviceException $e ) {
			//JWT uses invalid kid/guid
			throw new \gcgov\framework\exceptions\routeException( $e->getMessage(), 401, $e );
		}
		catch( \Lcobucci\JWT\Encoding\CannotDecodeContent|\Lcobucci\JWT\Token\UnsupportedHeaderFound|\Lcobucci\JWT\Token\InvalidTokenStructure $e ) {
			//JWT did not parse
			throw new \gcgov\framework\exceptions\routeException( 'Token parsing failed', 401, $e );
		}
		catch( \Lcobucci\JWT\Validation\RequiredConstraintsViolated $e ) {
			//JWT parsed successfully but failed validation
			$violations        = $e->violations();
			$violationMessages = [];
			foreach( $violations as $violation ) {
				$violationMessages[] = $violation->getMessage();
			}
			throw new \gcgov\framework\exceptions\routeException( 'Token validation failed: ' . implode( ', ', $violationMessages ), 401, $e );
		}

		//verify user roles allow them to access this resource
		if( count( $routeHandler->requiredRoles )>0 ) {
			foreach( $routeHandler->requiredRoles as $requiredRole ) {
				if( !in_array( $requiredRole, $authUser->roles ) ) {
					throw new \gcgov\framework\exceptions\routeException( 'User does not have permission to access this content', 403 );
				}
			}
		}

		//user has been authenticated
		return true;
	}


	/**
	 * Processed after lifecycle is complete with this instance
	 */
	public static function _after(): void {
	}


	/**
	 * Processed prior to __constructor() being called
	 */
	public static function _before(): void {
	}

}
