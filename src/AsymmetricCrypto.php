<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto;


use Hawk\HawkiCrypto\Exception\SeclibCryptoActionException;
use Hawk\HawkiCrypto\Value\AsymmetricKeypair;
use Hawk\HawkiCrypto\Value\AsymmetricPrivateKey;
use Hawk\HawkiCrypto\Value\AsymmetricPublicKey;
use phpseclib3\Crypt\RSA;

readonly class AsymmetricCrypto
{
    protected Seclib $libsec;

    public function __construct(?Seclib $libsec = null)
    {
        $this->libsec = $libsec ?? new Seclib();
    }

    /**
     * Generates a new RSA keypair.
     *
     * @return AsymmetricKeypair
     */
    public function generateKeypair(): AsymmetricKeypair
    {
        $privateKey = $this->libsec->createKey(4096);
        $publicKey = $privateKey->getPublicKey();

        $privateKeyString = (string)$privateKey;
        $publicKeyString = (string)$publicKey;

        return new AsymmetricKeypair(
            privateKey: new AsymmetricPrivateKey(
                server: $privateKeyString,
                web: preg_replace('~-+BEGIN (?:RSA )?PRIVATE KEY-+|-+END (?:RSA )?PRIVATE KEY-+|\s~', '', $privateKeyString)
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
        $pemPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split($webPublicKey, 64) .
            "-----END PUBLIC KEY-----";

        return new AsymmetricPublicKey(
            server: $pemPublicKey,
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
        $pemPrivateKey = "-----BEGIN PRIVATE KEY-----\r\n" .
            chunk_split($webPrivateKey, 64) .
            "-----END PRIVATE KEY-----";

        return new AsymmetricPrivateKey(
            server: $pemPrivateKey,
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
        try {
            $pubKey = $this->libsec->load($publicKey->server)
                ->withPadding(RSA::ENCRYPTION_OAEP)
                ->withHash('sha256');

            $encrypted = $pubKey->encrypt($plaintext);
        } catch (\Throwable $e) {
            throw SeclibCryptoActionException::createForEncryption($e);
        }

        if($encrypted === false) {
            throw SeclibCryptoActionException::createForEncryption(new \RuntimeException(
                'Encryption failed, possibly due to an invalid public key or plaintext.'
            ));
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
        string               $ciphertext,
        #[\SensitiveParameter]
        AsymmetricPrivateKey $privateKey
    ): string
    {
        try {
            /** @var RSA\PrivateKey $privKey */
            $privKey = $this->libsec->load($privateKey->server)
                ->withPadding(RSA::ENCRYPTION_OAEP)
                ->withHash('sha256');

            $decrypted = $privKey->decrypt(base64_decode($ciphertext));
        } catch (\Throwable $e) {
            throw SeclibCryptoActionException::createForDecryption($e);
        }

        if ($decrypted === false) {
             throw SeclibCryptoActionException::createForDecryption(new \RuntimeException(
                'Decryption failed, possibly due to an invalid private key or ciphertext.'
             ));
        }

        return $decrypted;
    }
}
