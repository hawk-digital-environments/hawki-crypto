<?php
declare(strict_types=1);


namespace Hawk\HawkiCrypto\Value;


readonly class SymmetricCryptoValue implements \Stringable, \JsonSerializable
{
    use StringableValueTrait {
        fromStringList as fromStringListRoot;
    }

    public function __construct(
        public string $iv,
        public string $tag,
        public string $ciphertext,
    )
    {
    }

    protected function toStringList(): array
    {
        return [$this->iv, $this->tag, $this->ciphertext];
    }

    protected static function fromStringList(string ...$values): static
    {
        return static::fromStringListRoot(
            ...self::fixLegacyValues(...$values)
        );
    }

    /**
     * The older javascript implementation base64 encodes each part of the SymmetricCryptoValue.
     * This will cause issues when trying to decrypt values created with that implementation.
     * This method checks if the values are base64 encoded and decodes them if necessary.
     * @param string ...$values
     * @return array
     */
    protected static function fixLegacyValues(string ...$values): array
    {
        $isBase64Encoded = function(string $data): bool {
            $decoded = base64_decode($data, true);
            if($decoded === false) {
                return false; // Not base64 encoded
            }
            return base64_encode($decoded) === $data;
        };

        return array_map(function($value) use ($isBase64Encoded) {
            $fixedValue = $isBase64Encoded($value) ? base64_decode($value) : $value;
            if($fixedValue === false) {
                throw new \InvalidArgumentException("Invalid base64 encoded value: $value");
            }
            return $fixedValue;
        }, $values);
    }

}
