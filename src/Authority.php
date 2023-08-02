<?php
/**
* =====================================================================================
* Class for develop interoperation with Linkhub APIs.
* Functionalities are authentication for Linkhub api products, and to support
* several base infomation(ex. Remain point).
*
* This module uses curl and openssl for HTTPS Request. So related modules must
* be installed and enabled.
*
* http://www.linkhub.co.kr
* Author : Jeong Yohan (code@linkhubcorp.com)
* Contributor : Jeong Wooseok (code@linkhubcorp.com)
* Written : 2019-02-08
* Updated : 2023-08-02
*
* Thanks for your interest.
* We welcome any suggestions, feedbacks, blames or anythings.
*
* Update Log
* - 2023/08/02 AuthURL Setter added
* ======================================================================================
*/

namespace Linkhub;

class Authority
{
    const VERSION = '2.0';
    const ServiceURL = 'https://auth.linkhub.co.kr';
    const ServiceURL_Static = 'https://static-auth.linkhub.co.kr';
    const ServiceURL_GA = 'https://ga-auth.linkhub.co.kr';
    private $ServiceURL;
    private $__LinkID;
    private $__SecretKey;
    private $__requestMode = LINKHUB_COMM_MODE;
    private static $singleton = null;
    public static function getInstance($LinkID,$secretKey)
    {
        if(is_null(Authority::$singleton)) {
            Authority::$singleton = new Authority();
        }
        Authority::$singleton->__LinkID = $LinkID;
        Authority::$singleton->__SecretKey = $secretKey;
        return Authority::$singleton;
    }
    public function gzdecode($data){
        return gzinflate(substr($data, 10, -8));
    }

    public function getSecretKey(){
        return Authority::$singleton->__SecretKey;
    }

    public function getLinkID(){
        return Authority::$singleton->__LinkID;
    }
    public function ServiceURL($V){
        $this->ServiceURL = $V;
    }

    private function executeCURL($url,$header = array(),$isPost = false, $postdata = null) {
        $base_header = array();
        $base_header[] = 'User-Agent: PHP7 LINKHUB SDK';
        $base_header[] = 'Accept-Encoding: gzip,deflate';
        $arr_header = $header + $base_header;

        if($this->__requestMode != "STREAM") {
            $http = curl_init($url);
            if($isPost) {
                curl_setopt($http, CURLOPT_POST,1);
                curl_setopt($http, CURLOPT_POSTFIELDS, $postdata);
            }
            curl_setopt($http, CURLOPT_HTTPHEADER,$arr_header);
            curl_setopt($http, CURLOPT_RETURNTRANSFER, TRUE);
            curl_setopt($http, CURLOPT_ENCODING, 'gzip,deflate');
            $responseJson = curl_exec($http);
            $http_status = curl_getinfo($http, CURLINFO_HTTP_CODE);
            if ($responseJson != true){
                throw new LinkhubException(curl_error($http));
            }
            curl_close($http);
            if($http_status != 200) {
                throw new LinkhubException($responseJson);
            }
            return json_decode($responseJson);
        }
        else {
            if($isPost) {
                $params = array('http' => array(
                     'ignore_errors' => TRUE,
                     'method' => 'POST',
                     'protocol_version' => '1.0',
                     'content' => $postdata
                    ));
            } else {
            $params = array('http' => array(
                     'ignore_errors' => TRUE,
                     'method' => 'GET',
                     'protocol_version' => '1.0',
                    ));
            }
            if ($arr_header !== null) {
                $head = "";
                foreach($arr_header as $h) {
                    $head = $head . $h . "\r\n";
                }
                $params['http']['header'] = substr($head,0,-2);
            }
            $ctx = stream_context_create($params);
            $response = file_get_contents($url, false, $ctx);
            $is_gzip = 0 === mb_strpos($response , "\x1f" . "\x8b" . "\x08");
            if($is_gzip){
                $response = $this->gzdecode($response);
            }
            if ($http_response_header[0] != "HTTP/1.1 200 OK") {
                throw new LinkhubException($response);
            }
            return json_decode($response);
        }
    }
    public function getTime($useStaticIP = false, $useLocalTimeYN = true, $useGAIP = false)
    {
        if(is_null($useLocalTimeYN) || $useLocalTimeYN) {
            $replace_search = array("@","#");
            $replace_target = array("T","Z");

            $date = new \DateTime('now', new \DateTimeZone('UTC'));

            return str_replace($replace_search, $replace_target, $date->format('Y-m-d@H:i:s#'));
        }
        if($this->__requestMode != "STREAM") {

            $targetURL = $this->getTargetURL($useStaticIP, $useGAIP);

            $http = curl_init($targetURL.'/Time');
            curl_setopt($http, CURLOPT_RETURNTRANSFER, TRUE);
            $response = curl_exec($http);
            $http_status = curl_getinfo($http, CURLINFO_HTTP_CODE);
            if ($response != true){
                throw new LinkhubException(curl_error($http));
            }
            curl_close($http);
            if($http_status != 200) {
                throw new LinkhubException($response);
            }
            return $response;
        } else {
            $header = array();
            $header[] = 'Connection: close';
            $params = array('http' => array(
                 'ignore_errors' => TRUE,
                 'protocol_version' => '1.0',
                 'method' => 'GET'
            ));
            if ($header !== null) {
                $head = "";
                foreach($header as $h) {
                    $head = $head . $h . "\r\n";
                }
                $params['http']['header'] = substr($head,0,-2);
            }
            $ctx = stream_context_create($params);

            $targetURL = $this->getTargetURL($useStaticIP, $useGAIP);

            $response = (file_get_contents($targetURL.'/Time', false, $ctx));
            if ($http_response_header[0] != "HTTP/1.1 200 OK") {
                throw new LinkhubException($response);
            }
            return $response;
        }
    }
    public function getToken($ServiceID, $access_id, array $scope = array() , $forwardIP = null, $useStaticIP = false, $useLocalTimeYN = true, $useGAIP = false)
    {
        $xDate = $this->getTime($useStaticIP, $useLocalTimeYN, $useGAIP);
        $uri = '/' . $ServiceID . '/Token';
        $header = array();
        $TokenRequest = new TokenRequest();
        $TokenRequest->access_id = $access_id;
        $TokenRequest->scope = $scope;
        $postdata = json_encode($TokenRequest);
        $digestTarget = 'POST'.chr(10);
        $digestTarget = $digestTarget.base64_encode(hash('sha256',$postdata,true)).chr(10);
        $digestTarget = $digestTarget.$xDate.chr(10);
        if(!(is_null($forwardIP) || $forwardIP == '')) {
            $digestTarget = $digestTarget.$forwardIP.chr(10);
        }
        $digestTarget = $digestTarget.Authority::VERSION.chr(10);
        $digestTarget = $digestTarget.$uri;
        $digest = base64_encode(hash_hmac('sha256',$digestTarget,base64_decode(strtr($this->__SecretKey, '-_', '+/')),true));
        $header[] = 'x-lh-date: '.$xDate;
        $header[] = 'x-lh-version: '.Authority::VERSION;
        if(!(is_null($forwardIP) || $forwardIP == '')) {
            $header[] = 'x-lh-forwarded: '.$forwardIP;
        }
        $header[] = 'Authorization: LINKHUB '.$this->__LinkID.' '.$digest;
        $header[] = 'Content-Type: Application/json';
        $header[] = 'Connection: close';
        

        $targetURL = $this->getTargetURL($useStaticIP, $useGAIP);

        return $this->executeCURL($targetURL.$uri , $header,true,$postdata);
    }
    public function getBalance($bearerToken, $ServiceID, $useStaticIP = false, $useGAIP = false)
    {
        $header = array();
        $header[] = 'Authorization: Bearer '.$bearerToken;
        $header[] = 'Connection: close';

        $targetURL = $this->getTargetURL($useStaticIP, $useGAIP);
        $uri = '/'.$ServiceID.'/Point';

        $response = $this->executeCURL($targetURL.$uri, $header);
        return $response->remainPoint;
    }
    public function getPartnerBalance($bearerToken, $ServiceID, $useStaticIP = false, $useGAIP = false)
    {
        $header = array();
        $header[] = 'Authorization: Bearer '.$bearerToken;
        $header[] = 'Connection: close';

        $targetURL = $this->getTargetURL($useStaticIP, $useGAIP);
        $uri = '/'.$ServiceID.'/PartnerPoint';

        $response = $this->executeCURL($targetURL.$uri, $header);
        return $response->remainPoint;
    }
    /*
    * 파트너 포인트 충전 팝업 URL 추가 (2017/08/29)
    */
    public function getPartnerURL($bearerToken, $ServiceID, $TOGO, $useStaticIP = false, $useGAIP = false)
    {
        $header = array();
        $header[] = 'Authorization: Bearer '.$bearerToken;
        $header[] = 'Connection: close';

        $targetURL = $this->getTargetURL($useStaticIP, $useGAIP);
        $uri = '/'.$ServiceID.'/URL?TG='.$TOGO;

        $response = $this->executeCURL($targetURL.$uri, $header);
        return $response->url;
    }

    private function getTargetURL($useStaticIP, $useGAIP)
    {
        if(isset($this->ServiceURL)) {
            return $this->ServiceURL;
        }

        if($useGAIP){
            return Authority::ServiceURL_GA;
        } else if($useStaticIP){
            return Authority::ServiceURL_Static;
        } else {
            return Authority::ServiceURL;
        }
    }
}
class TokenRequest
{
    public $access_id;
    public $scope;
}
class LinkhubException extends \Exception
{
    public function __construct($response, Exception $previous = null) {
       $Err = json_decode($response);
       if(is_null($Err)) {
            parent::__construct($response, -99999999);
       }
       else {
            parent::__construct($Err->message, $Err->code);
       }
    }
    public function __toString() {
        return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
    }
}
?>
