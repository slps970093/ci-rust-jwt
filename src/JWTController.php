<?php
/**
 * JWT Controller 抽象層
 *
 * 檢查 JWT 是否合法以及超過時效
 *
 * @another Yu-Hsien, Chou
 */

namespace LittleChou\CiJWT;

use Restserver\Libraries\REST_Controller;
use Firebase\JWT\JWT;

abstract class JWTController extends REST_Controller
{
	const REST_REQUEST_GET = 'GET';

	const REST_REQUEST_POST = 'POST';

	const REST_REQUEST_PATCH = 'PATCH';

	const REST_REQUEST_DELETE = 'DELETE';

	/**
	 * @var array 忽略的Methods
	 */
	private $ignoreMethods;

	private $jwtAlg = 'HS256';

	public function __construct($config = 'rest')
	{
		parent::__construct($config);
	}

	/**
	 * 新增 methods name 到忽略清單中
	 * @param $requestMethods
	 * @param $methodName
	 * @return $this
	 * @throws \Exception
	 */
	public function addIgnoreMethod($requestMethods, $methodName)
	{
		$allowRequest = [
			self::REST_REQUEST_GET,
			self::REST_REQUEST_PATCH,
			self::REST_REQUEST_DELETE,
			self::REST_REQUEST_POST
		];
		if (!in_array($requestMethods, $allowRequest)) {
			throw new \Exception('request method error');
		}
		if (count($this->ignoreMethods) >= 0) {
			$this->ignoreMethods[$requestMethods] = $methodName;
		} else {
			// 判斷是否新增過了
			$count = count($this->ignoreMethods[$requestMethods]);
			if ($count >= 1) {
				// 如果有新增過的就不要在二次新增
				if (!in_array($methodName, $this->ignoreMethods[$requestMethods])) {
					$this->ignoreMethods[$requestMethods] = $methodName;
				}
			} else {
				$this->ignoreMethods[$requestMethods] = $methodName;
			}
		}
		return $this;
	}

	/**
	 * 取得 Client Jwt Token string
	 *
	 * @return string | false
	 */
	public function getJWTToken()
	{
		// get client header data
		$data = $this->input->get_request_header('Authorization');

		if (!empty($data)) {
			$tmp = explode('Bearer', $data);
			$token = trim($tmp[1]);
			return $token;
		}

		return false;
	}

	/**
	 * 中介層 用於 JWT 認證檢查
	 */
	private function middleware()
	{

	}


	/**
	 * 產生 JWT Token
	 * @param $data
	 * @return string
	 */
	public function createJWTToken($data)
	{
		$token = JWT::encode($data, 'demo-key', $this->jwtAlg);

		return $token;
	}

	/**
	 * JWT decode
	 * @param $token
	 * @return object
	 */
	public function decode($token)
	{
		$data = JWT::decode($token, 'demo-key', $this->jwtAlg);

		return $data;
	}
}
