<?php
/**
 * Filename TestUrlSigningHelper.php
 * @author: Richard Wharton
 * @licence: Copyright Richard Wharton 2015
 */
use RWhar\UrlSigningHelper;

/**
 * Class TestUrlSigningHelper
 */
class TestUrlSigningHelper extends PHPUnit_Framework_TestCase
{
    /**
     * Composer Autoload
     */
    public function __construct()
    {
        require_once __DIR__ . '/../vendor/autoload.php';
    }


    public function testGenerateToken()
    {
        $sut = new UrlSigningHelper();

        $this->assertEquals(16, strlen($sut->generateToken()), 'Method returns a 16 char string');
    }


    public function testGenerateKey()
    {
        $sut = new UrlSigningHelper();

        $this->assertEquals(32, strlen($sut->generateKey()), 'Method returns a 32 char string');
    }


    public function testGetNowPlusMinutes()
    {
        $sut = new UrlSigningHelper();

        $expected = time() + 60;

        $this->assertEquals($expected, $sut->getNowPlusMinutes(1), 'Adds 60 seconds.');
    }


    public function testGetNowPlusHours()
    {
        $sut = new UrlSigningHelper();

        $expected = time() + (60 * 60);

        $this->assertEquals($expected, $sut->getNowPlusHours(1), 'Adds 60 minutes.');
    }


    public function testGetNowPlusDays()
    {
        $sut = new UrlSigningHelper();

        $expected = time() + (24 * 60 * 60);

        $this->assertEquals($expected, $sut->getNowPlusDays(1), 'Adds 24 hours.');
    }


    public function testCreateSignedUrl()
    {
        $sut = new UrlSigningHelper();

        $url = 'http://test.com/?token=1234567890987654';
        $expires = time() + 60;
        $key = 'SECRET12123456788765432121TERCES';

        $signedUrl = $sut->createSignedUrl($url, $expires, $key);

        $this->assertTrue(is_string($signedUrl), 'Returns string.');
    }


    public function testValidateSignedUrl()
    {
        $sut = new UrlSigningHelper();

        $url = 'http://test.com/?token=1234567890987654';
        $expires = time() + 60;
        $key = 'SECRET12123456788765432121TERCES';

        $signedUrl = $sut->createSignedUrl($url, $expires, $key);

        $this->assertEquals('1234567890987654', $sut->validateSignedUrl($signedUrl, [$key]), 'Returns token.');
    }


    public function testSignatureExpires()
    {
        $sut = new UrlSigningHelper();

        $url = 'http://test.com/?token=1234567890987654';
        $expires = time() - 1;
        $key = 'SECRET12123456788765432121TERCES';

        $signedUrl = $sut->createSignedUrl($url, $expires, $key);

        $this->assertEquals(false, $sut->validateSignedUrl($signedUrl, [$key]), 'Expires token.');
    }


    public function testTamperingInvalidatesSignature()
    {
        $sut = new UrlSigningHelper();

        $url = 'http://test.com/?token=1234567890987654';
        $key = 'SECRET12123456788765432121TERCES';

        $expires = time() + 60;

        $signedUrl = $sut->createSignedUrl($url, $expires, $key);

        parse_str(parse_url($signedUrl, PHP_URL_QUERY), $query);

        $expiresLater = $expires + 14;

        $tamperedUrl1 = $url . '&expires=' . $expiresLater . '&signature=' . $query['signature'];
        $tamperedUrl2 = 'http://test.com/delete/?token=1234567890987654' . '&expires=' . $expires . '&signature=' . $query['signature'];
        $tamperedUrl3 = $url . '&expires=' . $expires . '&signature=' . substr($query['signature'], 0, -1) . '4';

        $this->assertEquals(false, $sut->validateSignedUrl($tamperedUrl1, [$key]), 'Tampering with expiry invalidates signature.');
        $this->assertEquals(false, $sut->validateSignedUrl($tamperedUrl2, [$key]), 'Tampering with url invalidates signature.');
        $this->assertEquals(false, $sut->validateSignedUrl($tamperedUrl3, [$key]), 'Tampering with signature invalidates signature.');
    }


    public function testMalformedUrlSchemeDetectedOnCreation()
    {
        $this->setExpectedException('LogicException');
        $sut = new UrlSigningHelper();

        $url = 'httptest.com/?token=1234567890987654';
        $key = 'SECRET12123456788765432121TERCES';

        $expires = time() + 60;

        $sut->createSignedUrl($url, $expires, $key);
    }


    public function testMalformedUrlHostDetectedOnCreation()
    {
        $this->setExpectedException('LogicException');

        $sut = new UrlSigningHelper();

        $url = 'http:///?token=1234567890987654';
        $key = 'SECRET12123456788765432121TERCES';

        $expires = time() + 60;

        $sut->createSignedUrl($url, $expires, $key);
    }


    public function testMalformedUrlQueryDetectedOnCreation()
    {
        $this->setExpectedException('LogicException');
        $sut = new UrlSigningHelper();

        $url = 'httptest.com?token=1234567890987654';
        $key = 'SECRET12123456788765432121TERCES';

        $expires = time() + 60;

        $sut->createSignedUrl($url, $expires, $key);
    }



    public function testMalformedUrlSchemeDetectedOnValidation()
    {
        $this->setExpectedException('LogicException');
        $sut = new UrlSigningHelper();

        $url = 'httptest.com/?token=1234567890987654';
        $key = 'SECRET12123456788765432121TERCES';

        $expires = time() + 60;

        $sut->createSignedUrl($url, $expires, $key);
    }


    public function testMalformedUrlHostDetectedOnValidation()
    {
        $this->setExpectedException('LogicException');

        $sut = new UrlSigningHelper();

        $url = 'http:///?token=1234567890987654';
        $key = 'SECRET12123456788765432121TERCES';

        $expires = time() + 60;

        $sut->createSignedUrl($url, $expires, $key);
    }


    public function testMalformedUrlQueryDetectedOnValidation()
    {
        $this->setExpectedException('LogicException');
        $sut = new UrlSigningHelper();

        $url = 'httptest.com?token=1234567890987654';
        $key = 'SECRET12123456788765432121TERCES';

        $expires = time() + 60;

        $sut->createSignedUrl($url, $expires, $key);
    }
}
