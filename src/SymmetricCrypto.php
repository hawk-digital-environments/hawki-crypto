<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto;


use Hawk\HawkiCrypto\Exception\OpensslCryptoActionException;
use Hawk\HawkiCrypto\Value\SymmetricCryptoValue;

readonly class SymmetricCrypto
{
    protected OpenSsl $openSsl;

    public function __construct(?OpenSsl $openssl = null)
    {
        $this->openSsl = $openssl ?? new OpenSsl();
    }

    /**
     * Generates a random passphrase for symmetric encryption.
     * @return string
     */
    public function generatePassphrase(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Encrypts the given data using AES-256-GCM symmetric encryption.
     * The data is first base64 encoded to ensure it is in a suitable format for encryption.
     *
     * @param string $plaintext The data to encrypt.
     * @param string $passphrase The passphrase used for encryption.
     * @return SymmetricCryptoValue The encrypted value containing IV, tag, and ciphertext.
     */
    public function encrypt(
        string $plaintext,
        #[\SensitiveParameter]
        string $passphrase
    ): SymmetricCryptoValue
    {
        $plaintext = base64_encode($plaintext);
        $iv = random_bytes(12);
        $ciphertext = $this->openSsl->encrypt(
            $plaintext,
            'aes-256-gcm',
            $passphrase,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if($ciphertext === false){
            throw OpensslCryptoActionException::createForEncryption();
        }

        return new SymmetricCryptoValue(
            iv: $iv,
            tag: $tag,
            ciphertext: $ciphertext
        );
    }

    /**
     * Decrypts the given SymmetricCryptoValue using the provided passphrase.
     * The method uses AES-256-GCM decryption to retrieve the original data.
     *
     * @param SymmetricCryptoValue $value The encrypted value containing IV, tag, and ciphertext.
     * @param string $passphrase The passphrase used for decryption.
     * @return string The decrypted plaintext, base64 decoded.
     */
    public function decrypt(
        SymmetricCryptoValue $value,
        #[\SensitiveParameter]
        string               $passphrase
    ): string
    {
        $decrypted = $this->openSsl->decrypt(
            $value->ciphertext,
            'aes-256-gcm',
            $passphrase,
            OPENSSL_RAW_DATA,
            $value->iv,
            $value->tag
        );

        if($decrypted === false){
            throw OpensslCryptoActionException::createForDecryption();
        }

        return base64_decode($decrypted);
    }
}
