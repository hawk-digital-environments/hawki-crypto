<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto\Exception;


class OpensslCryptoActionException extends \RuntimeException implements HawkiCryptoExceptionInterface
{
    public static function createForEncryption(): self
    {
        return new self(
            'The encryption failed. ' . self::collectReasonString(),
        );
    }

    public static function createForDecryption(): self
    {
        return new self(
            'The decryption failed. ' . self::collectReasonString(),
        );
    }

    protected static function collectReasonString(): string
    {
        $reasons = [];
        while ($reason = openssl_error_string()) {
            $reasons[] = $reason;
        }
        if(empty($reasons)) {
            return 'Something unknown, but wrong happend in the OpenSSL action.';
        }

        return 'The OpenSSL action failed with the following reasons: ' . implode(', ', $reasons);
    }

}
