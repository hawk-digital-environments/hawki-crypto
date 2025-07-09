<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto\Tests;

use Hawk\HawkiCrypto\Exception\OpensslCryptoActionException;
use Hawk\HawkiCrypto\OpenSsl;
use Hawk\HawkiCrypto\SymmetricCrypto;
use Hawk\HawkiCrypto\Value\SymmetricCryptoValue;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OpensslCryptoActionException::class)]
#[CoversClass(SymmetricCrypto::class)]
class SymmetricCryptoTest extends TestCase
{
    public function testItCanGenerateARandomPassphrase(): void
    {
        $sut = new SymmetricCrypto();
        $passphrase = $sut->generatePassphrase();
        $this->assertIsString($passphrase);
        $this->assertNotEmpty($passphrase);
        $this->assertEquals(32, strlen($passphrase));
    }

    public function testItCanEncryptAndDecrypt(): void
    {
        $sut = new SymmetricCrypto();
        $passphrase = $sut->generatePassphrase();

        $plaintext = 'This is a test message.';
        $encrypted = $sut->encrypt(
            plaintext: $plaintext,
            passphrase: $passphrase
        );
        $this->assertInstanceOf(SymmetricCryptoValue::class, $encrypted);
        $this->assertNotEmpty($encrypted->ciphertext);
        $this->assertNotEquals($encrypted->ciphertext, $plaintext);
        $decrypted = $sut->decrypt(
            value: $encrypted,
            passphrase: $passphrase
        );

        $this->assertSame($plaintext, $decrypted);
    }

    public function testItFailsToEncryptOnOpenSslError(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $openSsl = $this->createMock(OpenSsl::class);
        $openSsl->method('encrypt')
            ->willReturn(false);
        $sut = new SymmetricCrypto($openSsl);
        $sut->encrypt(
            plaintext: 'This is a test message.',
            passphrase: 'invalid-passphrase'
        );
    }

    public function testItFailsToDecryptOnOpenSslError(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $openSsl = $this->createMock(OpenSsl::class);
        $openSsl->method('decrypt')
            ->willReturn(false);
        $sut = new SymmetricCrypto($openSsl);
        $sut->decrypt(
            value: new SymmetricCryptoValue(
                iv: random_bytes(12),
                tag: random_bytes(16),
                ciphertext: 'invalid-ciphertext'
            ),
            passphrase: 'invalid-passphrase'
        );
    }
}
