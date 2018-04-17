<?php
namespace ecloud;

class ecloud
{
    const OATH2_URL_AUTHORIZE = 'https://cloud.189.cn/open/oauth2/authorize.action';
    const OATH2_URL_ACCESS_TOKEN = 'https://cloud.189.cn/open/oauth2/accessToken.action';
    
    public $app_key;
    public $app_secret;
    public $callback_url;
    
    private $now_time;
    private $app_signature;
    private $access_token;
    
    public function __construct($app_key = '', $app_secret = '')
    {
        $this->app_key   = $app_key;
        $this->app_secret = $app_secret;
        
        $this->now_time = time();
    }
    
    public function getAuthorize()
    {
        $query = array('appKey'=>$this->app_key, 'responseType'=>'code');
        $query['callbackUrl'] = $this->callback_url;
        $query['display'] = 'default';
        $query['timestamp'] = $this->now_time;
        $query['appSignature'] = $this->getAppSignature();
        
        $content = $this->curlGet(self::OATH2_URL_AUTHORIZE, $query);
    }
    
    public function getAccessToken()
    {
        $query = array('appKey'=>$this->app_key, 'grantType'=>'authorization_code');
        $query['timestamp'] = $this->now_time;
        $query['appSignature'] = $this->getAppSignature();
        
        $content = $this->curlGet(self::OATH2_URL_ACCESS_TOKEN, $query);
    }
    
    public function curlGet($url, $query = array(), $header = array())
    {
        if (!empty($query)) $url .= '?'.http_build_query($query);
        
        $http_header = $this->getCommonHeader('GET', $url, $header);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        // curl_setopt($ch, CURLOPT_HEADER, true);
        if ($http_header) curl_setopt($ch, CURLOPT_HTTPHEADER, $http_header);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $content = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return array('code'=>$code, 'content'=>$content);
    }
    
    public function curlPut($url, $post = array(), $header = array())
    {
        $http_header = $this->getCommonHeader('PUT', $url, $header);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT'); 
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        if ($http_header) curl_setopt($ch, CURLOPT_HTTPHEADER, $http_header);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $content = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return array('code'=>$code, 'content'=>$content);
    }
    
    public function curlPost($url, $post = array(), $header = array())
    {
        $http_header = $this->getCommonHeader('POST', $url, $header);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        if ($http_header) curl_setopt($ch, CURLOPT_HTTPHEADER, $http_header);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $content = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return array('code'=>$code, 'content'=>$content);
    }
    
    private function getCommonHeader($method, $url, $header)
    {
        $http_header = [];
        if ($this->access_token) {
            $path = parse_url($url, PHP_URL_PATH);
            $date = gmdate('D, d M Y H:i:s T');
            $http_header[] = 'AccessToken: '.$this->access_token;
            $http_header[] = 'Signature: '.$this->getSignature($method, $path, $date);
            $http_header[] = 'Date: '.$date;
        }
        
        if (!empty($header)) {
            foreach ($header as $k => $v) {
                $http_header[] = $k.': '.$v;
            }
        }
        
        return $http_header;
    }
    
    private function getAppSignature()
    {
        if (!$this->app_signature) {
            $this->app_signature = hash_hmac('sha1', 'appKey='.$this->app_key.'&timestamp='.$this->now_time, $this->app_secret);
        }
        
        return $this->app_signature;
    }
    
    private function getSignature($operate, $url, $date)
    {
        return hash_hmac('sha1', 'AccessToken='.$this->access_token.'&Operate='.$operate.'&RequestURI='.$url.'&Date='.$date, $this->app_secret);
    }
}