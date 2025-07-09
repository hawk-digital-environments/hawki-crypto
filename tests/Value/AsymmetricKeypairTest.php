<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto\Tests;


use Hawk\HawkiCrypto\Exception\InvalidNumberOfStringPartsException;
use Hawk\HawkiCrypto\Value\AsymmetricKeypair;
use Hawk\HawkiCrypto\Value\AsymmetricPrivateKey;
use Hawk\HawkiCrypto\Value\AsymmetricPublicKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(AsymmetricKeypair::class)]
class AsymmetricKeypairTest extends TestCase
{
    protected AsymmetricKeypair $sut;

    protected function setUp(): void
    {
        $this->sut = new AsymmetricKeypair(
            privateKey: new AsymmetricPrivateKey(
                server: 'server-private-key',
                web: 'web-private-key'
            ),
            publicKey: new AsymmetricPublicKey(
                server: 'server-key',
                web: 'web-key'
            )
        );
    }

    public function testItCanBeConstructed(): void
    {
        $sut = new AsymmetricKeypair(
            privateKey: $this->createStub(AsymmetricPrivateKey::class),
            publicKey: $this->createStub(AsymmetricPublicKey::class)
        );
        $this->assertInstanceOf(AsymmetricKeypair::class, $sut);
    }

    public function testItCanBeConvertedToString(): void
    {
        $this->assertSame('YzJWeWRtVnlMWEJ5YVhaaGRHVXRhMlY1fGQyVmlMWEJ5YVhaaGRHVXRhMlY1|YzJWeWRtVnlMV3RsZVE9PXxkMlZpTFd0bGVRPT0=', (string)$this->sut);
    }

    public function testItCanBeCreatedFromString(): void
    {
        $sut = AsymmetricKeypair::fromString('YzJWeWRtVnlMWEJ5YVhaaGRHVXRhMlY1fGQyVmlMWEJ5YVhaaGRHVXRhMlY1|YzJWeWRtVnlMV3RsZVE9PXxkMlZpTFd0bGVRPT0=');

        $this->assertInstanceOf(AsymmetricKeypair::class, $sut);
        $this->assertSame('server-key', $sut->publicKey->server);
        $this->assertSame('web-key', $sut->publicKey->web);
    }

    public function testItCanBeJsonEncoded(): void
    {
        $json = json_encode($this->sut);
        $this->assertSame('"YzJWeWRtVnlMWEJ5YVhaaGRHVXRhMlY1fGQyVmlMWEJ5YVhaaGRHVXRhMlY1|YzJWeWRtVnlMV3RsZVE9PXxkMlZpTFd0bGVRPT0="', $json);
    }

    public function testItFailsToBeCreatedFromStringWithNotEnoughParts(): void
    {
        $this->expectException(InvalidNumberOfStringPartsException::class);
        AsymmetricKeypair::fromString(
            'asdf'
        );
    }
}
