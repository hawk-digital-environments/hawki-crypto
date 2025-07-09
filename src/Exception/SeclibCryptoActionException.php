<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto\Exception;


class SeclibCryptoActionException extends \RuntimeException implements HawkiCryptoExceptionInterface
{
    public static function createForEncryption(\Throwable $previous): self
    {
        return new self(
            'The encryption failed. ' . $previous->getMessage(),
            previous: $previous
        );
    }

    public static function createForDecryption(\Throwable $previous): self
    {
        return new self(
            'The decryption failed. ' . $previous->getMessage(),
            previous: $previous
        );
    }
}
