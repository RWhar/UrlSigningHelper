# URL Signing Helper

Provides utility methods to assist with the creation and validation of signed web links.

## Methods

- createSignedUrl
- validateSignedUrl
- generateKey
- generateToken
- getNowPlusMinutes
- getNowPlusHours
- getNowPlusDays

## Example Usage

```php
$urlHelper = new UrlSigningHelper();

// Store the key, if cycling key mark others as inactive and set their expiry
$key = $urlHelper->generateKey();

// Store the token and expiry for the request, ensure the token is unique
$token = $urlHelper->generateToken();
$expires = $urlHelper->getNowPlusMinutes(1);

$url = $urlHelper->createSignedUrl(
    'https://my.mysite.com/test?with=qs&token=' . $token,
    $expires,
    $key
);

echo "Use this link: " . $url . "\n";

$keys = [$key]; // Get active and non-expired keys
$token = $urlHelper->validateSignedUrl($url, $keys);

if (!$token) {
    exit('The URL is not valid.');
}

// Lookup by token
echo $token;
```