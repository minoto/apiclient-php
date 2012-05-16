<?php
class OAuthSignatureMethodHMAC_SHA1 implements IOAuthSignatureMethod {

    /**
     * Sign an OAuth request with HMAC-SHA1 method.
     *
     * This code is copied from the 'oauth-php' library available from http://code.google.com/p/oauth-php/
     * 
     * @see IOAuthSignatureMethod::sign()
     * @author Marc Worrell <marcw@pobox.com>
     * @date  Sep 8, 2008 12:21:19 PM
     *
     * The MIT License
     *
     * Copyright (c) 2007-2008 Mediamatic Lab
     *
     * Permission is hereby granted, free of charge, to any person obtaining a copy
     * of this software and associated documentation files (the "Software"), to deal
     * in the Software without restriction, including without limitation the rights
     * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
     * copies of the Software, and to permit persons to whom the Software is
     * furnished to do so, subject to the following conditions:
     *
     * The above copyright notice and this permission notice shall be included in
     * all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
     * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
     * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
     * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
     * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
     * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
     * THE SOFTWARE.
     */
    function sign($base_string, $consumer_secret, $token_secret) {
        $key = OAuthUtil::urlencode($consumer_secret).'&'.OAuthUtil::urlencode($token_secret);
        if (function_exists('hash_hmac')) {
            $signature = base64_encode(hash_hmac("sha1", $base_string, $key, true));
        } else {
            $blocksize  = 64;
            $hashfunc   = 'sha1';
            if (strlen($key) > $blocksize)
            {
                $key = pack('H*', $hashfunc($key));
            }
            $key    = str_pad($key,$blocksize,chr(0x00));
            $ipad   = str_repeat(chr(0x36),$blocksize);
            $opad   = str_repeat(chr(0x5c),$blocksize);
            $hmac   = pack(
                    'H*',$hashfunc(
                            ($key^$opad).pack(
                                    'H*',$hashfunc(
                                            ($key^$ipad).$base_string
                                    )
                            )
                    )
            );
            $signature = base64_encode($hmac);
        }
        return OAuthUtil::urlencode($signature);
    }
}
?>