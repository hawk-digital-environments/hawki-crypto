<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto\Tests;


use Hawk\HawkiCrypto\AsymmetricCrypto;
use Hawk\HawkiCrypto\Exception\OpensslCryptoActionException;
use Hawk\HawkiCrypto\OpenSsl;
use Hawk\HawkiCrypto\Value\AsymmetricKeypair;
use Hawk\HawkiCrypto\Value\AsymmetricPrivateKey;
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
            privateKey: new AsymmetricPrivateKey(
                server: 'invalid-private-key',
                web: 'invalid-private-key-web'
            )
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
            privateKey: new AsymmetricPrivateKey(
                server: 'invalid-private-key',
                web: 'invalid-private-key-web'
            )
        );
    }

    public function testItCanLoadPublicKeyFromAWebSource(): void
    {
        $sut = new AsymmetricCrypto();
        $publicKey = $sut->generateKeypair()->publicKey;

        $loadedPublicKey = $sut->loadPublicKeyFromWeb($publicKey->web);

        $this->assertEquals($publicKey->server, $loadedPublicKey->server);
    }

    public function testItFailsToLoadPublicKeyFromWebSourceIfInvalidValueWasGiven(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $sut = new AsymmetricCrypto();
        $sut->loadPublicKeyFromWeb('invalid-public-key');
    }

    public function testItCanLoadPrivateKeyFromAWebSource(): void
    {
        $sut = new AsymmetricCrypto();
        $privateKey = $sut->generateKeypair()->privateKey;

        $loadedPrivateKey = $sut->loadPrivateKeyFromWeb($privateKey->web);

        $this->assertEquals($privateKey->server, $loadedPrivateKey->server);
    }

    public function testItFailsToLoadPrivateKeyFromWebSourceIfInvalidKey(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $sut = new AsymmetricCrypto();
        $sut->loadPrivateKeyFromWeb('invalid-private-key');
    }

    public function testITFailsToLoadPrivateKeyFromWebSourceIfKeyCanNotBeExported(): void
    {
        $this->expectException(OpensslCryptoActionException::class);
        $openSsl = $this->createMock(OpenSsl::class);
        $openSsl->method('pkey_get_private')
            ->willReturn(true);
        $openSsl->method('pkey_export')
            ->willReturn(false);
        $sut = new AsymmetricCrypto($openSsl);
        $sut->loadPrivateKeyFromWeb('invalid-private-key');

    }

    public function testItCanEncryptAndDecryptWithAWebGeneratedKeypair(): void
    {
        $publicKey = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA42iWtZ0Z4L+/aG0eaz5bDlx/8/5kgFV3SGs6Fnkawz/Z+brdPESQ5X4OYr14p8nq5RpBh+Plq466EWK6pspc+xnbYbgHVoQqN+R4Z55TZo4bb+/Vxd0BR7xL2lJPk4I1S7COTexIx91hWLrG+hPCOoQoQn+FKdCHUbbaNngrSLJ3qcTZ06LPCpwCqD/OoRG0Bs3ymTri5beGnt2Lq3c3VGUP9BmqJRqT0nTTb1Mpcc32MOaAVsWiQTkMYUdvgaiI1YTiZy186VEfQLv6GhZixOxbEex6mt9xT5r8UQDuYFKldh9A/f/D6z4jF9xzB0hDuAWofXozd7qWkot0+fV1/UEDqSjAJd2ru5aPHI0eraZflX2ekyhQL5LQFl1cNtdvKuR4Ix/kCcMbCBjbBaI6OR5VqN9xn/3WFSiZkaJwUYCC07F9adJUeHAlc4fFESG69jE7wccu+OVynf/uviQkg4QhqCRBVRn0KSOoAiGxsoAXI8Y57j6rE5ANiPc+qyzIF8BDZ4DUeNv2T2eyIq4xUuhS20YDZ/rsG45+1iTgN+W1JXDGUi9WOoPF6FMlpEceUOP5Y7+9H4NLfBSc7eGH/eN5Vl/xJjfdaDz9G9oPQxcqYMq+s5j/jP+Zu59Orn+agwzO3RZ7MnwKHmozs4ZSrCsKimaMU5ox3Df1c+zOOyECAwEAAQ==';
        $privateKey = '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';
        $sut = new AsymmetricCrypto();
        $loadedPublicKey = $sut->loadPublicKeyFromWeb($publicKey);
        $loadedPrivateKey = $sut->loadPrivateKeyFromWeb($privateKey);
        $this->assertequals($publicKey, $loadedPublicKey->web);

        $cipher = $sut->encrypt(
            plaintext: 'This is a test message.',
            publicKey: $loadedPublicKey
        );

        $this->assertNotEmpty($cipher);

        $decrypted = $sut->decrypt(
            ciphertext: $cipher,
            privateKey: $loadedPrivateKey
        );

        $this->assertSame('This is a test message.', $decrypted);
    }

}
