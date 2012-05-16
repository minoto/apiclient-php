<?php
class OAuthSignatureMethodPlaintext implements IOAuthSignatureMethod {
    function sign($base_string, $consumer_secret, $token_secret) {
        $key = OAuthUtil::urlencode($consumer_secret).'&'.OAuthUtil::urlencode($token_secret);
        return OAuthUtil::urlencode($key);
    }
}
?>