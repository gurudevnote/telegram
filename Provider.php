<?php

namespace SocialiteProviders\Telegram;

use Illuminate\Support\Facades\Validator;
use InvalidArgumentException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use \Laravel\Socialite\Two\User;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'TELEGRAM';

    public static function additionalConfigKeys(): array
    {
        return ['bot'];
    }

    protected function getAuthUrl($state): string
    {
        return null;
    }

    protected function getTokenUrl(): string
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        $name = trim(sprintf('%s %s', $user['first_name'] ?? '', $user['last_name'] ?? ''));

        return (new User)->setRaw($user)->map([
            'id'        => $user['id'],
            'nickname'  => $user['username'] ?? $user['first_name'],
            'name'      => ! empty($name) ? $name : null,
            'avatar'    => $user['photo_url'] ?? null,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $pramKeyValues = explode('&', $token);

        $paramas = [];

        foreach ($pramKeyValues as $keyValue) {
            $keyValues = explode('=', $keyValue);
            if (count($keyValues) === 2) {
                $paramas[$keyValues[0]] = rawurldecode($keyValues[1]);
            }
        }

        $validator = Validator::make($paramas, [
            'id'        => 'required|numeric',
            'auth_date' => 'required|date_format:U|before:1 day',
            'hash'      => 'required|size:64',
        ]);

        throw_if($validator->fails(), InvalidArgumentException::class);

        $hash = $paramas['hash'];
        unset($paramas['hash']);

        $dataToHash = collect($paramas)
            ->transform(fn ($val, $key) => "$key=$val")
            ->sort()
            ->join("\n");

        $hash_key = hash('sha256', $this->clientSecret, true);
        $hash_hmac = hash_hmac('sha256', $dataToHash, $hash_key);

        throw_if(
            $hash !== $hash_hmac,
            InvalidArgumentException::class
        );

        unset($paramas['auth_date']);

        return $paramas;
    }
}