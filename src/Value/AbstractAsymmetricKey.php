<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto\Value;


abstract readonly class AbstractAsymmetricKey implements \Stringable, \JsonSerializable
{
    use StringableValueTrait;

    public string $server;
    public string $web;

    public function __construct(
        #[\SensitiveParameter]
        string $server,
        #[\SensitiveParameter]
        string $web
    )
    {
        $this->server = $server;
        $this->web = $web;
    }

    protected function toStringList(): array
    {
        return [$this->server, $this->web];
    }

}
