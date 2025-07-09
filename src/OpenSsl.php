<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto;

/**
 * A wrapper for OpenSSL functions to make them easier to use and test.
 * @codeCoverageIgnore
 */
class OpenSsl
{
    /**
     * @see openssl_encrypt()
     */
    public function encrypt(
        string $data,
        string $cipher_algo,
        string $passphrase,
        int $options = 0,
        string $iv = "",
        mixed &$tag = null,
        string $aad = "",
        int $tag_length = 16
    )
    {
        return openssl_encrypt(
            $data,
            $cipher_algo,
            $passphrase,
            $options,
            $iv,
            $tag,
            $aad,
            $tag_length
        );
    }

    /**
     * @see openssl_decrypt()
     */
    public function decrypt(
        string $data,
        string $cipher_algo,
        string $passphrase,
        int $options = 0,
        string $iv = "",
        mixed $tag = null,
        string $aad = ""
    ) {
        return openssl_decrypt(
            $data,
            $cipher_algo,
            $passphrase,
            $options,
            $iv,
            $tag,
            $aad
        );
    }
}
