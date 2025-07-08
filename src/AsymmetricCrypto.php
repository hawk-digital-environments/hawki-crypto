<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto;


use Hawk\HawkiCrypto\Exception\OpensslCryptoActionException;
use Hawk\HawkiCrypto\Value\AsymmetricKeypair;
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

        $privateKeyEncoded = base64_encode($privateKeyString);
        $keyDetails = $this->openSsl->pkey_get_details($privateKeyRes);
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
        $pubKey = $this->openSsl->pkey_get_public(base64_decode($publicKey->server));
        if($pubKey === false) {
            throw OpensslCryptoActionException::createForGeneric('Invalid public key provided.');
        }

        if(!$this->openSsl->public_encrypt($plaintext, $encrypted, $pubKey)){
            throw OpensslCryptoActionException::createForEncryption();
        }

        return base64_encode($encrypted);
    }

    /**
     * Decrypts data using the provided private key.
     * This method uses the RSA private key to decrypt the data.
     *
     * @param string $ciphertext The ciphertext to decrypt, base64-encoded.
     * @param string $privateKey The private key to use for decryption, base64-encoded.
     * @return string The decrypted plaintext.
     */
    public function decrypt(
        string $ciphertext,
        #[\SensitiveParameter]
        string $privateKey
    ): string
    {
        $privKey = $this->openSsl->pkey_get_private(base64_decode($privateKey));
        if($privKey === false){
            throw OpensslCryptoActionException::createForGeneric('The private key is invalid.');
        }

        if(!$this->openSsl->private_decrypt(base64_decode($ciphertext), $decrypted, $privKey)){
            throw OpensslCryptoActionException::createForDecryption();
        }

        return $decrypted;
    }
}
