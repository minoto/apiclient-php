<?php

require_once dirname(__FILE__) . "/oauthutil.php";
require_once dirname(__FILE__) . "/signatures/ioauthsignaturemethod.interface.php";
require_once dirname(__FILE__) . "/signatures/plaintext.php";
require_once dirname(__FILE__) . "/signatures/hmac_sha1.php";

class APIClient {

    private $host;
    private $consumer_key;
    private $consumer_secret;
    private $access_token;
    private $token_secret;

    private $curl;

    private $method;
    private $path;
    private $querystring;
    private $url;
    private $response;
    private $headers;
    private $defaultHeaders;

    private $put_file_handler;
    private $put_file_length;

    private $post_data;

    private $acting_account_id;

    public function __construct($host, $consumer_key, $consumer_secret, $access_token, $token_secret, $user_agent = "'Minoto PHP APIClient v0.1") {
        $this->host = $host;
        $this->consumer_key = $consumer_key;
        $this->consumer_secret = $consumer_secret;
        $this->access_token = $access_token;
        $this->token_secret = $token_secret;
        $this->user_agent = $user_agent;
        $this->defaultHeaders[] = 'Accept: +php';
        $this->acting_account_id = null;
    }

    public function setActingAccount($account_id) {
        $this->acting_account_id = $account_id;
    }

    protected function setPath($path, array $query_variables = array()) {
        $added_query_variables = array();

        $pos = strpos($path, '?');
        if($pos !== false) {
            $querystring = substr($path, $pos + 1);
            $path = substr($path, 0, $pos);
            $added_query_variables = $this->parseQueryString($querystring);
        }

        $this->path = $path;
        $this->given_parameters = array_merge($query_variables, $added_query_variables);

    }

    public function get($path, $query_variables = array()) {
        $this->headers = $this->defaultHeaders;

        $this->method = 'get';
        $this->setPath($path, $query_variables);
        $first = true;

        return $this->doRequest();
    }

    public function put($path, $object) {
        $this->headers = $this->defaultHeaders;
        $this->headers[] = 'Content-Type: +php';
        $this->method = 'put';
        $this->setPath($path);

        $data = serialize($object);
        $this->put_file_length = strlen($data);
        $this->put_file_handler = tmpfile();
        fwrite($this->put_file_handler, $data);
        fseek($this->put_file_handler, 0);
        return $this->doRequest();
    }

    public function post($path, $object) {
        $this->headers = $this->defaultHeaders;
        $this->headers[] = 'Content-Type: +php';

        $this->method = 'post';
        $this->setPath($path);

        $this->post_data = serialize($object);

        return $this->doRequest();
    }

    public function delete($path) {
        $this->headers = $this->defaultHeaders;
        $this->method = 'delete';
        $this->setPath($path);

        return $this->doRequest();
    }

    private function doRequest() {

        $this->curl = curl_init();


        if($this->acting_account_id != null) {
            $this->given_parameters['acting_account'] = $this->acting_account_id;
        }

        $this->url = 'http://'. $this->host . $this->path;
        $querystring = $this->buildQueryString($this->given_parameters);
        if(strlen($querystring)) {
            $this->url .= '?' . $querystring;
        }

        curl_setopt($this->curl, CURLOPT_USERAGENT, $this->user_agent);
        // Return transfer as a string instead of outputting
        curl_setopt($this->curl, CURLOPT_RETURNTRANSFER, true);
        // Return header in the output
        curl_setopt($this->curl, CURLOPT_HEADER, true);

        switch($this->method) {
            case 'get':
                break;
            case 'put':
                curl_setopt($this->curl, CURLOPT_PUT, true);
                curl_setopt($this->curl, CURLOPT_INFILE, $this->put_file_handler);
                curl_setopt($this->curl, CURLOPT_INFILESIZE, $this->put_file_length);
                break;
            case 'post':
                curl_setopt($this->curl, CURLOPT_POST, true);
                curl_setopt($this->curl, CURLOPT_POSTFIELDS, $this->post_data);
                break;
            case 'delete':
                curl_setopt($this->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
                break;
        }

        $this->headers[] = $this->getOAuthHeader();

        curl_setopt($this->curl, CURLOPT_HTTPHEADER, $this->headers);
        curl_setopt($this->curl, CURLOPT_URL, $this->url);
        $return = curl_exec($this->curl);
        if($return === false) {
            throw new APIClientException("Failed to execute request.");
        }
        $this->response = $this->parseCurlReturn($return);

        curl_close($this->curl);

        if($this->response['code'][0] == '2'){
            if($this->response['code'] == '204') return null;
            return $this->getObject();
        } else {
            $errors = $this->getErrors();
            throw new APIException($errors);
        }
    }

    private function getOAuthHeader() {
        $parameters = $this->getParameters();
         


        $signature_base_string_parts = array();
        $signature_base_string_parts[] = strtoupper($this->method);
        $signature_base_string_parts[] = 'http://'. $this->host . $this->path;
        $signature_base_string_parts[] = $this->getNormalizedRequestParameters($parameters);

        // Encode all parts and concatenate with ampersands
        $base_string = implode('&', array_map(array('OAuthUtil', 'urlencode'), $signature_base_string_parts));

        // Create signer
        $signature_method = str_replace('-', '_', $parameters['oauth_signature_method']);
        $classname = "OAuthSignatureMethod" . $signature_method;
        $signer = new $classname();

        // Create signature
        $signature = $signer->sign($base_string, $this->consumer_secret, $this->token_secret);
        $parameters['oauth_signature'] = $signature;

        $header = 'Authorization: OAuth realm="http://'. $this->host . '"';
        foreach($parameters as $name => $parameter) {
            $header .= "," . $name . '="' . $parameter . '"';
        }

        return $header;
    }

    public function getBody() {
        return $this->response['body'];
    }

    public function getObject() {
        $object = @unserialize($this->response['body']);
        if($object === false) {
            $this->printStderr("Problem deserializing API response:");
            ob_start();
            print_r($this->response);
            $this->printStderr(ob_get_clean());
            throw new APIClientException("Minoto API error. Failed to process result.");
        }
        return $object;
    }

    /**
     * Split a querystring into an array of key/values. This differs from the php function parse_str as this does not parse arrays.
     * @param string $string
     */
    public function parseQueryString($string) {
        $variables = array();

        if(!strlen($string)) {
            return array();
        }

        $parts = explode('&', $string);
        foreach($parts as $part) {
            list($key, $value) = explode('=', $part, 2);
            $variables[$key] = $value;
        }

        return $variables;

    }

    /**
     * Create a querystring from an array of key/values. This differs from the php function http_build_query as this does not escape [ and ] in keys
     * @param $variables
     */
    public function buildQueryString(array $variables) {
        $parts = array();
        foreach($variables as $key => $value) {
            $parts[] = rawurlencode($key) . '=' . rawurlencode($value);
        }
        return implode('&', $parts);
    }

    public function getErrors() {
        try {
            $errorobjects = $this->getObject();
        } catch(Exception $e) {
            $errorobjects = null;
        }

        if(!is_array($errorobjects)){
            $errorobject = new stdClass;
            $errorobject->code = "500";
            $errorobject->message = "Invalid response from API.";
            $errorobjects = array($errorobject);
        }

        return $errorobjects;
    }

    private function parseCurlReturn($return) {
        if (empty($return))
        {
            return array();
        }

        @list($headers,$body) = explode("\r\n\r\n",$return,2);
        $lines = explode("\r\n",$headers);

        if (preg_match('@^HTTP/[0-9]\.[0-9] +100@', $lines[0]))
        {
            /* HTTP/1.x 100 Continue
             * the real data is on the next line
            */
            @list($headers,$body) = explode("\r\n\r\n",$body,2);
            $lines = explode("\r\n",$headers);
        }

        // first line of headers is the HTTP response code
        $http_line = array_shift($lines);
        if (preg_match('@^HTTP/[0-9]\.[0-9] +([0-9]{3})@', $http_line, $matches))
        {
            $code = $matches[1];
        }

        $headers = array();
        foreach ($lines as $line)
        {
            list($key, $value) = explode(': ', $line, 2);
            $headers[strtolower($key)] = $value;
        }

        return array('code' => $code,
                'headers' => $headers,
                'body' => $body);
    }

    private function getParameters() {
        $params = $this->given_parameters;

        $params['oauth_consumer_key'] = $this->consumer_key;
        $params['oauth_signature_method'] = 'HMAC-SHA1';
        $params['oauth_timestamp'] = time();
        $params['oauth_nonce'] = uniqid();
        $params['oauth_version'] = '1.0';
        $params['oauth_token'] = $this->access_token;
        return $params;
    }

    public function getHttpStatusCode() {
        return $this->response['code'];
    }

    private function getNormalizedRequestParameters($params) {
        $normalized = array();

        ksort($params);
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                $value_sort = $value;
                sort($value_sort);
                foreach ($value_sort as $v) {
                    $normalized[] = OAuthUtil::urlencode($key).'='.OAuthUtil::urlencode($v);
                }
            } else {
                $normalized[] = OAuthUtil::urlencode($key).'='. OAuthUtil::urlencode($value);
            }
        }
        return implode('&', $normalized);
    }

    function printStderr($message) {
        fwrite(STDERR, $message . PHP_EOL);
    }
}

/**
 * A real exception, connection failed, output not serialized php, 500 error from server, etc.
 */
class APIClientException extends Exception {}

/**
 * A regular error from the API, where we retrieved error messages from the API
 */
class APIException extends Exception {

    private $errors;

    public function __construct(array $errors) {
        parent::__construct();
        $this->errors = $errors;
    }

    public function getErrors() {
        return $this->errors;
    }
}
