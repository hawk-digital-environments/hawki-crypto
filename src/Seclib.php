<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto;


use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\Crypt\Common\PublicKey as CommonPublicKey;
use phpseclib3\Crypt\Common\PrivateKey as CommonPrivateKey;

/**
 * @codeCoverageIgnore External wrapper to allow tests to mock the libsec library.
 */
class Seclib
{
    public function createKey($bits = 2048): PrivateKey {
        return RSA::createKey($bits);
    }

    public function load($key, $password = false): PublicKey | PrivateKey | CommonPublicKey | CommonPrivateKey
    {
        return RSA::load($key, $password);
    }
}
