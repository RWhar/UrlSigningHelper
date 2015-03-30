<?php
/**
 * Filename UrlSigningHelper.php
 * @author: Richard Wharton
 * @licence: Copyright Richard Wharton 2015
 */
namespace RWhar;

use LogicException;
use RuntimeException;

/**
 * UrlSigningHelper - Provides methods to sign and verify URL's.
 *
 * Secret keys should be stored and cycled at regular intervals (~1 per month). Upon key change, previous key should
 * be kept, but marked inactive, and set to expire in t - MAX_ACTIVE_DURATION_HOURS
 *
 * Usage:
 *
 *  $urlHelper = new UrlSigningHelper();
 *
 *  // Store the key, when cycling the signing key mark others as inactive and set their
 *  // expiry to the current time + MAX_ACTIVE_DURATION_HOURS
 *  $key = $urlHelper->generateKey();
 *
 *  // Store the token and expiry for the request, ensure the token is unique
 *  $token = $urlHelper->generateToken();
 *  $expires = $urlHelper->getNowPlusMinutes(1);
 *
 *  $url = $urlHelper->createSignedUrl(
 *      'https://my.site.com/test?with=qs&token=' . $token,
 *      $expires,
 *      $key
 *  );
 *
 *  echo "Use this link: " . $url . "\n";
 *
 *  $keys = [$key]; // Get array of all non-expired signing keys
 *  $token = $urlHelper->validateSignedUrl($url, $keys);
 *
 *  if (!$token) {
 *    exit('The URL is not valid.');
 *  }
 *
 *  // Complete authenticated action and deactivate token
 *  echo $token;
 *
 */
class UrlSigningHelper
{
    /** Maximum time until expiry, recommended seven days */
    const MAX_ACTIVE_DURATION_HOURS = 168;

    /** SHA1 | SHA256 (DEFAULT) | SHA512 */
    const HMAC_HASH_ALGO = 'SHA256';

    /**
     * Check platform dependencies
     *
     * @throws RuntimeException On missing dependency
     */
    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('This library requires the extension php_openssl');
        }
    }


    /**
     * Create short-lived, signed urls
     *
     * The secret key should be stored for at least [time-of-last-signing] + MAX_ACTIVE_DURATION_HOURS
     *
     * @param string $url An unsigned URL with 16 character token in query parameters
     * @param int $expires A Unix Timestamp matching date of URL expiry
     * @param string $secretKey Secret key to sign requests with, must be at least 32 chars
     *
     * @return string The signed URL string
     * @throws LogicException On reserved parameter names found in URL query string
     * @throws LogicException On missing or invalid token in URL query string
     * @throws LogicException On expiry date greater than maximum allowed
     */
    public function createSignedUrl($url, $expires, $secretKey) {
        parse_str(parse_url($url, PHP_URL_QUERY), $queryParams);

        $urlScheme = parse_url($url, PHP_URL_SCHEME);

        if ($urlScheme == false || parse_url($url, PHP_URL_HOST) == false) {
            throw new LogicException('URL is malformed.');
        }

        if (array_intersect(['expires', 'signature'], array_keys($queryParams))) {
            throw new LogicException('Query parameters "expires" and "signature" are reserved.');
        }

        if (!array_key_exists('token', $queryParams) || strlen($queryParams['token']) != 16) {
            throw new LogicException('16 char "token" parameter not found in url query string.');
        }

        if (strlen($secretKey) < 32) {
            throw new LogicException('Secret key must be at least 32 chars.');
        }

        if ($expires > (time() + self::MAX_ACTIVE_DURATION_HOURS)) {
            throw new LogicException('Expiry timestamp greater than maximum allowed 7 days.');
        }

        $queryParams['expires'] = $expires;

        $fullUrl = http_build_url($url, ['query' => http_build_query($queryParams)]);

        $signature = base64_encode(hash_hmac(self::HMAC_HASH_ALGO, $fullUrl, $secretKey, true));
        $queryParams['signature'] = $signature;
        $fullQuery = http_build_query($queryParams);

        $signedUrl = http_build_url($fullUrl, ['query' => $fullQuery]);

        return $signedUrl;
    }


    /**
     * Check a signed URL for validity against the provided set of keys
     *
     * Both the active key and any non-expired keys should be passed to transition between keys
     *
     * @param string $url The signed URL to check
     * @param array $secretKeys An array of secret keys to validate URL with
     *
     * @return string|bool Returns token if URL if valid else false
     * @throws LogicException On invalid url input
     * @throws LogicException On empty secretKeys array
     */
    public function validateSignedUrl($url, array $secretKeys)
    {
        if (!is_string($url) || strlen($url) < 5) {
            throw new LogicException('First argument URL must be a valid URL of type string,');
        }

        if (count($secretKeys) < 1) {
            throw new LogicException('Secret keys array must contain at least one item.');
        }

        $scheme = parse_url($url, PHP_URL_SCHEME);
        $host = parse_url($url, PHP_URL_HOST);
        $path = parse_url($url, PHP_URL_PATH);
        parse_str(parse_url($url, PHP_URL_QUERY), $query);

        if (!array_key_exists('signature', $query)) {
            return false;
        }

        $providedSignature = $query['signature'];
        unset($query['signature']);

        $parts['scheme'] = $scheme;
        $parts['host'] = $host;
        $parts['path'] = $path;
        $parts['query'] = http_build_query($query);

        $rebuiltUrl = http_build_url('', $parts);

        if (substr($rebuiltUrl, -1, 1) === '?') {
            $rebuiltUrl = substr($rebuiltUrl, 0, -1);
        }

        if ((int) $query['expires'] <= time()) {
            return false;
        }

        $match = false;

        foreach ($secretKeys as $key) {
            $computedSignature = base64_encode(hash_hmac(self::HMAC_HASH_ALGO, $rebuiltUrl, $key, true));

            if ($providedSignature === $computedSignature) {
                $match = true;
                break;
            }
        }

        return $match ? $query['token'] : false;
    }


    /**
     * Generate a valid token to add to your URL query parameters
     *
     * This should be stored somewhere along with the expiry timestamp
     *
     * @return string A random 16 character token
     */
    public function generateToken()
    {
        $token = bin2hex(openssl_random_pseudo_bytes('8'));

        return $token;
    }


    /**
     * Generate a URL signing key
     *
     * @return string A random 32 character key
     */
    public function generateKey()
    {
        $key = bin2hex(openssl_random_pseudo_bytes('16'));

        return $key;
    }


    /**
     * Get current unix timestamp plus n minutes
     *
     * For creation of expiry parameters
     *
     * @param int $minutes The number of minutes to add to current time
     *
     * @return int The resultant Unix Timestamp
     */
    public function getNowPlusMinutes($minutes)
    {
        $seconds = $minutes * 60;

        return time() + $seconds;
    }


    /**
     * Get current unix timestamp plus n hours
     *
     * For creation of expiry parameters
     *
     * @param int $hours The number of hours to add to current time
     *
     * @return int The resultant Unix Timestamp
     */
    public function getNowPlusHours($hours)
    {
        $seconds = $hours * 60 * 60;

        return time() + $seconds;
    }


    /**
     * Get current unix timestamp plus n days
     *
     * For creation of expiry parameters
     *
     * @param int $days The number of days to add to current time
     *
     * @return int The resultant Unix Timestamp
     */
    public function getNowPlusDays($days)
    {
        $seconds = $days * 24 * 60 * 60;

        return time() + $seconds;
    }
}
