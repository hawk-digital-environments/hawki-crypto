<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto;


use Hawk\HawkiCrypto\Exception\OpensslCryptoActionException;
use Hawk\HawkiCrypto\Value\AsymmetricKeypair;
use Hawk\HawkiCrypto\Value\AsymmetricPrivateKey;
use Hawk\HawkiCrypto\Value\AsymmetricPublicKey;

readonly class AsymmetricCrypto
{
    protected OpenSsl $openSsl;

    public function __construct(?OpenSsl $openssl = null)
    {
        $this->openSsl = $openssl ?? new OpenSsl();
    }

    /**
     * Generates a new RSA keypair.
     *
     * @return AsymmetricKeypair
     */
    public function generateKeypair(): AsymmetricKeypair
    {
        $privateKeyRes = $this->openSsl->pkey_new([
            'private_key_bits' => 4096,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if($privateKeyRes === false) {
            throw OpensslCryptoActionException::createForGeneric('Failed to generate private key.');
        }

        if(!$this->openSsl->pkey_export($privateKeyRes, $privateKeyString)){
            throw OpensslCryptoActionException::createForGeneric('The creation of a keypair failed.');
        }

        $keyDetails = $this->openSsl->pkey_get_details($privateKeyRes);
        $publicKeyString = $keyDetails['key'];

        return new AsymmetricKeypair(
            privateKey: new AsymmetricPrivateKey(
                server: $privateKeyString,
                web: preg_replace('~-+BEGIN PRIVATE KEY-+|-+END PRIVATE KEY-+|\s~', '', $privateKeyString)
            ),
            publicKey: new AsymmetricPublicKey(
                server: $publicKeyString,
                web: preg_replace('~-+BEGIN PUBLIC KEY-+|-+END PUBLIC KEY-+|\s~', '', $publicKeyString)
            )
        );
    }

    /**
     * This method loads a public key from a string that has been created in a browser context.
     * The web public key will be converted into a PEM format, which is required by OpenSSL.
     * @param string $webPublicKey
     * @return AsymmetricPublicKey
     */
    public function loadPublicKeyFromWeb(string $webPublicKey): AsymmetricPublicKey
    {
        $pemPublicKey = "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split($webPublicKey, 64, "\n") .
            "-----END PUBLIC KEY-----";

        $loadedPubKey = $this->openSsl->pkey_get_public($pemPublicKey);
        if($loadedPubKey === false) {
            throw OpensslCryptoActionException::createForGeneric('The public key is invalid.');
        }

        $keyDetails = $this->openSsl->pkey_get_details($loadedPubKey);

        return new AsymmetricPublicKey(
            server: $keyDetails['key'],
            web: $webPublicKey
        );
    }

    /**
     * This method loads a private key from a string that has been created in a browser context.
     * The web private key will be converted into a PEM format, which is required by OpenSSL.
     * @param string $webPrivateKey
     * @return AsymmetricPrivateKey
     */
    public function loadPrivateKeyFromWeb(string $webPrivateKey): AsymmetricPrivateKey
    {
        $pemPrivateKey = "-----BEGIN PRIVATE KEY-----\n" .
            chunk_split($webPrivateKey, 64, "\n") .
            "-----END PRIVATE KEY-----";
        $loadedPrivateKey = $this->openSsl->pkey_get_private($pemPrivateKey);
        if($loadedPrivateKey === false) {
            throw OpensslCryptoActionException::createForGeneric('The private key is invalid.');
        }

        if(!$this->openSsl->pkey_export($loadedPrivateKey, $privateKeyString)){
            throw OpensslCryptoActionException::createForGeneric('The private key could not be exported.');
        }

        return new AsymmetricPrivateKey(
            server: $privateKeyString,
            web: $webPrivateKey
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
        $pubKey = $this->openSsl->pkey_get_public($publicKey->server);
        if($pubKey === false) {
            throw OpensslCryptoActionException::createForGeneric('Invalid public key provided.');
        }

        if(!$this->openSsl->public_encrypt($plaintext, $encrypted, $pubKey, OPENSSL_PKCS1_OAEP_PADDING)){
            throw OpensslCryptoActionException::createForEncryption();
        }

        return base64_encode($encrypted);
    }

    /**
     * Decrypts data using the provided private key.
     * This method uses the RSA private key to decrypt the data.
     *
     * @param string $ciphertext The ciphertext to decrypt, base64-encoded.
     * @param AsymmetricPrivateKey $privateKey The private key to use for decryption, base64-encoded.
     * @return string The decrypted plaintext.
     */
    public function decrypt(
        string $ciphertext,
        #[\SensitiveParameter]
        AsymmetricPrivateKey $privateKey
    ): string
    {
        $privKey = $this->openSsl->pkey_get_private($privateKey->server);
        if($privKey === false){
            throw OpensslCryptoActionException::createForGeneric('The private key is invalid.');
        }

        if(!$this->openSsl->private_decrypt(base64_decode($ciphertext), $decrypted, $privKey, OPENSSL_PKCS1_OAEP_PADDING)){
            throw OpensslCryptoActionException::createForDecryption();
        }

        return $decrypted;
    }
}
