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
     * @see openssl_pkey_new()
     */
    public function pkey_new(?array $options)
    {
        return openssl_pkey_new($options);
    }

    /**
     * @see openssl_pkey_export())
     */
    public function pkey_export($key, &$output, ?string $passphrase = null, ?array $options = null)
    {
        return openssl_pkey_export($key, $output, $passphrase, $options);
    }

    /**
     * @see openssl_pkey_get_public()
     */
    public function pkey_get_public($public_key)
    {
        return openssl_pkey_get_public($public_key);
    }

    /**
     * @see openssl_pkey_get_private()
     */
    public function pkey_get_private($private_key, ?string $passphrase = null)
    {
        return openssl_pkey_get_private($private_key, $passphrase);
    }

    /**
     * @see openssl_public_encrypt()
     */
    public function public_encrypt(
        string $data,
               &$encrypted_data,
               $public_key,
        int    $padding = OPENSSL_PKCS1_PADDING
    )
    {
        return openssl_public_encrypt($data, $encrypted_data, $public_key, $padding);
    }

    /**
     * @see openssl_private_decrypt()
     */
    public function private_decrypt(
        string $data,
               &$decrypted_data,
               $private_key,
        int    $padding = OPENSSL_PKCS1_PADDING
    )
    {
        return openssl_private_decrypt($data, $decrypted_data, $private_key, $padding);
    }

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
