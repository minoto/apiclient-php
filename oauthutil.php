<?php
class OAuthUtil {
    
    
    /**
     * Encode a string according to the RFC3986
     * 
     * @param string s
     * @return string
     */
    static function urlencode ( $s )
    {
        if ($s === false)
        {
            return $s;
        }
        else
        {
            return str_replace('%7E', '~', rawurlencode($s));
        }
    }
    
    /**
     * Decode a string according to RFC3986.
     * Also correctly decodes RFC1738 urls.
     * 
     * @param string s
     * @return string
     */
    static function urldecode ( $s )
    {
        if ($s === false)
        {
            return $s;
        }
        else
        {
            return rawurldecode($s);
        }
    }

    /**
     * urltranscode - make sure that a value is encoded using RFC3986.
     * We use a basic urldecode() function so that any use of '+' as the
     * encoding of the space character is correctly handled.
     * 
     * @param string s
     * @return string
     */
    static function urltranscode ( $s )
    {
        if ($s === false)
        {
            return $s;
        }
        else
        {
            return self::urlencode(urldecode($s));
        }
    }
    
    
    
}