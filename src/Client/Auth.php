<?php

namespace Now\Client;

use GuzzleHttp\HandlerStack;
use GuzzleHttp\Client;
use GuzzleHttp\Middleware;
use GuzzleHttp\RetryMiddleware;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class Auth
{
    const DEFAULT_INCREMENTAL_RETRY_IS_ACTIVE = false;
    const DEFAULT_MAX_RETRIES = 5;
    const DEFAULT_MAX_DELAY_BETWEEN_RETRIES_IN_SECONDS = 60;
    CONST HTTP_UNAUTHORISED = 401;

    protected HandlerStack $handlerStack;
    public Client $client;
    public array $options;

    /**
     * Auth constructor.
     * @param Config $config
     */
    public function __construct(Config $config)
    {
        $this->buildHandler();

        $this->client = new Client([
            'handler' => $this->handlerStack,
            // URL for access_token request
            'base_uri' => $config->base_uri,
            'Connection' => 'close',
            CURLOPT_FORBID_REUSE => true,
            CURLOPT_FRESH_CONNECT => true,
        ]);

        $this->options = ['form_params' =>
            [
                'grant_type' => 'password',
                'client_id' => $config->client_id,
                'client_secret' => $config->client_secret,
                'username' => $config->username,
                'password' => $config->password,
            ]
        ];
    }

    /**
     * @return mixed
     */
    public function getToken($tokenRefreshed = false)
    {
        // Try and retrieve a valid oauth token
        $cachedToken = Cache::get('servicenow_oauth_token');
        $options = $this->options;

        if ($tokenRefreshed) {
            $options['headers']['X-Token-Refreshed'] = $tokenRefreshed;
        }

        if ($cachedToken == null) {
            $response = $this->client->post('/oauth_token.do', $options);
            $decodedResponse = json_decode($response->getBody());
            $cachedToken = $decodedResponse->access_token;
            Cache::put('servicenow_oauth_token', $cachedToken, now()->addSeconds($decodedResponse->expires_in));
        }
        return $cachedToken;
    }

    protected function buildHandler()
    {
        $this->handlerStack = HandlerStack::create();
        $incrementalRetryIsActive = config('http_client.incremental_retry_is_active') ?? self::DEFAULT_INCREMENTAL_RETRY_IS_ACTIVE;
        if ($incrementalRetryIsActive) {
            $this->handlerStack->push(Middleware::retry($this->shouldAttemptRetry(), $this->setDelay()));
        }
    }

    protected function shouldAttemptRetry()
    {
        $maxRetries = config('http_client.max_retries') ?? self::DEFAULT_MAX_RETRIES;
        $retryResponseCodes = config('http_client.retry_response_codes') ?? '';
        $retryResponseCodes = !empty($retryResponseCodes) ? explode(',', $retryResponseCodes) : [];

        return function (
            $retries,
            RequestInterface &$request,
            ResponseInterface $response = null,
            \Exception $exception = null
        ) use ($maxRetries, $retryResponseCodes) {
            $headers = $request->getHeaders();
            $tokenRefreshed = false;
            if (array_key_exists('X-Token-Refreshed', $headers)) {
                $tokenRefreshed = $headers['X-Token-Refreshed'][0];
            }
            $statusCode = $response->getStatusCode();
            $doRetry = $retries < $maxRetries && ($exception instanceof \Exception
                    || in_array($statusCode, $retryResponseCodes));

            if ($doRetry && $tokenRefreshed && $retries > 0) {
                $doRetry = false;
            }

            if ($doRetry) {
                $uri = $request->getUri();
                Log::warning('Retrying request', [
                    'retry_attempt' => $retries + 1,
                    'uri' => $uri->getScheme() . '://' . $uri->getHost() . $uri->getPath() . '?' . $uri->getQuery(),
                    'body' => $request->getBody()->getContents(),
                ]);


                if ($retries === ($maxRetries - 1) && $statusCode === self::HTTP_UNAUTHORISED) {
                    Cache::forget('servicenow_oauth_token');
                    $tokenRefreshed = true;
                    $newToken = $this->getToken($tokenRefreshed);
                    $request = $request->withHeader('Authorization', 'Bearer ' . $newToken)
                        ->withHeader('X-Token-Refreshed', $tokenRefreshed);
                }
            }

            return $doRetry;
        };
    }

    protected function setDelay()
    {
        $maxDelayBetweenRetriesInSeconds = config('http_client.max_delay_between_retries_in_seconds')
            ?? self::DEFAULT_MAX_DELAY_BETWEEN_RETRIES_IN_SECONDS;

        return function ($retries) use ($maxDelayBetweenRetriesInSeconds) {
            return min(($maxDelayBetweenRetriesInSeconds * 1000), RetryMiddleware::exponentialDelay($retries));
        };
    }
}