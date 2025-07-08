<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto\Tests;


use Hawk\HawkiCrypto\AsymmetricCrypto;
use Hawk\HawkiCrypto\Exception\OpensslCryptoActionException;
use Hawk\HawkiCrypto\OpenSsl;
use Hawk\HawkiCrypto\Value\AsymmetricKeypair;
use Hawk\HawkiCrypto\Value\AsymmetricPublicKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OpensslCryptoActionException::class)]
#[CoversClass(AsymmetricCrypto::class)]
class AsymmetricCryptoTest extends TestCase
{
    public function testItCanGenerateAKeypair(): void
    {
        $sut = new AsymmetricCrypto();
        $keypair = $sut->generateKeypair();
        $this->assertInstanceOf(AsymmetricKeypair::class, $keypair);
        $this->assertNotEmpty($keypair->privateKey);
        $this->assertInstanceOf(AsymmetricPublicKey::class, $keypair->publicKey);
        $this->assertNotEmpty($keypair->publicKey->server);
        $this->assertNotEmpty($keypair->publicKey->web);
        $this->assertNotSame(
            $keypair->publicKey->server,
            $keypair->publicKey->web
        );
    }

    public function testItFailsToGenerateAKeypairIfOpenSslCanNotCreatePkey(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $openSsl = $this->createMock(OpenSsl::class);
        $openSsl->method('pkey_new')
            ->willReturn(false);
        $sut = new AsymmetricCrypto($openSsl);
        $sut->generateKeypair();
    }

    public function testItFailsToGenerateAKeypairIfOpenSslCanNotExportPkey(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $openSsl = $this->createMock(OpenSsl::class);
        $openSsl->method('pkey_new')
            ->willReturn(true);
        $openSsl->method('pkey_export')
            ->willReturn(false);
        $sut = new AsymmetricCrypto($openSsl);
        $sut->generateKeypair();
    }

    public function testItCanEncryptAndDecrypt(): void
    {
        $sut = new AsymmetricCrypto();
        $keypair = $sut->generateKeypair();

        $plaintext = 'This is a test message.';
        $encrypted = $sut->encrypt(
            plaintext: $plaintext,
            publicKey: $keypair->publicKey
        );

        $this->assertNotEmpty($encrypted);

        $decrypted = $sut->decrypt(
            ciphertext: $encrypted,
            privateKey: $keypair->privateKey
        );

        $this->assertSame($plaintext, $decrypted);
    }

    public function testItFailsToEncryptIfOpenSslCanNotGetPublicKey(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $sut = new AsymmetricCrypto();
        $sut->encrypt(
            plaintext: 'This is a test message.',
            publicKey: new AsymmetricPublicKey('invalid-public-key', 'invalid-public-key-web')
        );
    }

    public function testItFailsToEncryptOnOpenSslError(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $openSsl = $this->createMock(OpenSsl::class);
        $openSsl->method('pkey_get_public')
            ->willReturn(true);
        $openSsl->method('public_encrypt')
            ->willReturn(false);
        $sut = new AsymmetricCrypto($openSsl);
        $sut->encrypt(
            plaintext: 'This is a test message.',
            publicKey: new AsymmetricPublicKey('invalid-public-key', 'invalid-public-key-web')
        );
    }

    public function testItFailsToDecryptIfOpenSslCanNotGetPrivateKey(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $sut = new AsymmetricCrypto();
        $sut->decrypt(
            ciphertext: 'This is a test message.',
            privateKey: 'invalid-private-key'
        );
    }

    public function testItFailsToDecryptOnOpenSslError(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $openSsl = $this->createMock(OpenSsl::class);
        $openSsl->method('pkey_get_private')
            ->willReturn(true);
        $openSsl->method('private_decrypt')
            ->willReturn(false);
        $sut = new AsymmetricCrypto($openSsl);
        $sut->decrypt(
            ciphertext: 'This is a test message.',
            privateKey: 'invalid-private-key'
        );
    }

}
