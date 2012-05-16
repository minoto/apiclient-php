<?php
interface IOAuthSignatureMethod {
    public function sign($base_string, $consumer_secret, $token_secret);
}