<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto;


use Hawk\HawkiCrypto\Value\AsymmetricKeypair;
use Hawk\HawkiCrypto\Value\AsymmetricPublicKey;

readonly class AsymmetricCrypto
{
    /**
     * Generates a new RSA keypair.
     *
     * @return AsymmetricKeypair
     */
    public function generateKeypair(): AsymmetricKeypair
    {
        $privateKeyRes = openssl_pkey_new([
            'private_key_bits' => 4096,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($privateKeyRes, $privateKeyString);
        $privateKeyEncoded = base64_encode($privateKeyString);
        $keyDetails = openssl_pkey_get_details($privateKeyRes);
        $publicKeyString = $keyDetails['key'];

        return new AsymmetricKeypair(
            privateKey: $privateKeyEncoded,
            publicKey: new AsymmetricPublicKey(
                server: base64_encode($publicKeyString),
                web: preg_replace('~-+BEGIN PUBLIC KEY-+|-+END PUBLIC KEY-+|\s~', '', $publicKeyString)
            )
        );
    }

    /**
     * Encrypts data using the provided public key.
     * This method uses the RSA public key to encrypt the data.
     *
     * @param string $plaintext The data to encrypt.
     * @param AsymmetricPublicKey $publicKey The public key to use for encryption.
     * @return string The ciphertext, base64-encoded.
     */
    public function encrypt(string $plaintext, AsymmetricPublicKey $publicKey): string
    {
        $pubKey = openssl_pkey_get_public(base64_decode($publicKey->server));
        openssl_public_encrypt($plaintext, $encrypted, $pubKey);
        return base64_encode($encrypted);
    }

    /**
     * Decrypts data using the provided private key.
     * This method uses the RSA private key to decrypt the data.
     *
     * @param string $data The ciphertext to decrypt, base64-encoded.
     * @param string $privateKey The private key to use for decryption, base64-encoded.
     * @return string The decrypted plaintext.
     */
    public function decrypt(
        string $data,
        #[\SensitiveParameter]
        string $privateKey
    ): string
    {
        $privKey = openssl_pkey_get_private(base64_decode($privateKey));
        openssl_private_decrypt(base64_decode($data), $decrypted, $privKey);
        return $decrypted;
    }
}
