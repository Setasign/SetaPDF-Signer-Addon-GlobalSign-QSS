<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Qss;

use InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

class Client
{
    public const TYPE_SIGNATURES = 'signatures';
    public const TYPE_TIMESTAMPS = 'timestamps';
    public const TYPE_USERS = 'users';

    /**
     * @var ClientInterface
     */
    protected $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    protected $requestFactory;

    /**
     * @var StreamFactoryInterface
     */
    protected $streamFactory;

    /**
     * @var string
     */
    protected $apiKey;

    /**
     * @var string
     */
    protected $apiSecret;

    /**
     * @var string
     */
    protected $apiUrl;

    /**
     * @var null|string
     */
    protected $accessToken;

    public function __construct(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        string $apiKey,
        string $apiSecret,
        string $apiUrl
    ) {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;
        $this->apiUrl = rtrim($apiUrl, '/');
    }

    /**
     * Helper method to handle errors in json_decode
     *
     * @param string $json
     * @param bool $assoc
     * @param int $depth
     * @param int $options
     * @return mixed
     */
    protected function json_decode(string $json, bool $assoc = true, int $depth = 512, int $options = 0)
    {
        // Clear json_last_error()
        \json_encode(null);

        $data = @\json_decode($json, $assoc, $depth, $options);

        if (\json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidArgumentException(\sprintf(
                'Unable to decode JSON: %s',
                \json_last_error_msg()
            ));
        }

        return $data;
    }

    /**
     * Login method.
     *
     * This method login to obtain a JWT token for authentication on further requests.
     * The access token is cached by the instance.
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#login_post
     * @return string The auth token
     * @throws UnexpectedResponseException If an error happens while processing the request.
     * @throws ClientExceptionInterface
     */
    public function login(): string
    {
        if ($this->accessToken !== null) {
            return $this->accessToken;
        }

        $body = json_encode([
            'api_key' => $this->apiKey,
            'api_secret' => $this->apiSecret,
        ]);

        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('POST', $this->apiUrl . '/login')
            ->withHeader('Content-Type', 'application/json;charset=utf-8')
            ->withHeader('Content-Length', \strlen($body))
            ->withBody($this->streamFactory->createStream($body))
        );
        
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }
        $responseData = $this->json_decode($response->getBody()->getContents());
        $this->accessToken = $responseData['access_token'];
        return $this->accessToken;
    }

    /**
     * Submit a request for a new user
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users_post
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @param string $givenName Given name used to identify the user
     * @param string $surname Surname used to identify the user
     * @param string $mobileNo Mobile number to verify a user request
     * @return string
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function createUser(string $email, string $givenName, string $surname, string $mobileNo): string
    {
        $body = json_encode([
            'email' => $email,
            'given_name' => $givenName,
            'surname' => $surname,
            'mobile_no' => $mobileNo,
        ]);

        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('POST', $this->apiUrl . '/users')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
            ->withHeader('Content-Type', 'application/json;charset=utf-8')
            ->withHeader('Content-Length', \strlen($body))
            ->withBody($this->streamFactory->createStream($body))
        );
        if ($response->getStatusCode() !== 201) {
            throw new UnexpectedResponseException($response);
        }
        $responseData = $this->json_decode($response->getBody()->getContents());
        return $responseData['user_id'];
    }

    /**
     * Retrieve the user
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__get
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @return array
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function getUser(string $email): array
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('GET', $this->apiUrl . '/users/' . $email)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }
        return $this->json_decode($response->getBody()->getContents());
    }

    /**
     * Update the user
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__patch
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @param string $givenName Given name used to identify the user
     * @param string $surname Surname used to identify the user
     * @param string $mobileNo Mobile number to verify a user request
     * @return void
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function updateUser(string $email, string $givenName, string $surname, string $mobileNo): void
    {
        $body = json_encode([
            'given_name' => $givenName,
            'surname' => $surname,
            'mobile_no' => $mobileNo,
        ]);

        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('PATCH', $this->apiUrl . '/users/' . $email)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
            ->withHeader('Content-Type', 'application/json;charset=utf-8')
            ->withHeader('Content-Length', \strlen($body))
            ->withBody($this->streamFactory->createStream($body))
        );
        if ($response->getStatusCode() !== 204) {
            throw new UnexpectedResponseException($response);
        }
    }

    /**
     * Delete a user
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__delete
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @return void
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function deleteUser(string $email): void
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('DELETE', $this->apiUrl . '/users/' . $email)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );
        if ($response->getStatusCode() !== 204) {
            throw new UnexpectedResponseException($response);
        }
    }

    /**
     * Retrieve the list of devices for a given user
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__devices_get
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @return array
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function getUserDevices(string $email): array
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('GET', $this->apiUrl . '/users/' . $email . '/devices')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }
        return $this->json_decode($response->getBody()->getContents());
    }

    /**
     * Delete a device
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__devices__deviceid__delete
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @param string $deviceId The device unique identifier
     * @return void
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function deleteUserDevice(string $email, string $deviceId): void
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('GET', $this->apiUrl . '/users/' . $email . '/devices/' . $deviceId)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );
        if ($response->getStatusCode() !== 204) {
            throw new UnexpectedResponseException($response);
        }
    }

    /**
     * Submit a request for a signing identity
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__identity_post
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @param array $subject_dn List of Distinguished Name attributes to include in the certificate. See RFC 5280#4.1.2.6
     * @return array
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function createUserIdentity(string $email, array $subject_dn = []): array
    {
        $body = json_encode([
            'subject_dn' => $subject_dn,
        ]);

        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('POST', $this->apiUrl . '/users/' . $email . '/identity')
                ->withHeader('Authorization', 'Bearer ' . $this->login())
                ->withHeader('Content-Type', 'application/json;charset=utf-8')
                ->withHeader('Content-Length', \strlen($body))
                ->withBody($this->streamFactory->createStream($body))
        );
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }
        return $this->json_decode($response->getBody()->getContents());
    }

    /**
     * Revoke the certificate and delete keys
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__identity_delete
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @return void
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function revokeUserIdentity(string $email)
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('DELETE', $this->apiUrl . '/users/' . $email . '/identity')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );
        if ($response->getStatusCode() !== 204) {
            throw new UnexpectedResponseException($response);
        }
    }

    /**
     * Retrieve signature for digest
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__sign__digest__get
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @param string $digest Hex encoded SHA256 message digest as defined in RFC5652#section-5.4
     * @return string Hex encoded SignatureValue as defined in RFC5652
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function sign(string $email, string $digest): string
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('GET', $this->apiUrl . '/users/' . $email . '/sign/' . $digest)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }
        return $this->json_decode($response->getBody()->getContents())['signature'];
    }

    /**
     * Retrieve signatures for multiple digests
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__sign_post
     * @param string $email Email address to verify a user request, the email address uniquely identifies the user for that organisation
     * @param string[] $digests List of Hex encoded SHA256 message digest as defined in RFC5652#section-5.4
     * @return string[] List of Hex encoded signatures as defined in RFC5652
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function signMultiple(string $email, array $digests): array
    {
        $body = json_encode([
            'digests' => $digests,
        ]);

        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('POST', $this->apiUrl . '/users/' . $email . '/sign')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
            ->withHeader('Content-Type', 'application/json;charset=utf-8')
            ->withHeader('Content-Length', \strlen($body))
            ->withBody($this->streamFactory->createStream($body))
        );
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }
        return $this->json_decode($response->getBody()->getContents())['signatures'];
    }

    /**
     * Retrieve timestamp token for digest
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#timestamp__digest__get
     * @param string $digest Hex encoded SHA2-256 digest of the object to be timestamped. Corresponds to MessageImprint hashedMesssage as defined in RFC3161.
     * @return string Base64 encoded DER representation of timestamp token according to RFC3161. It includes the TSA signing certificate in SignedData.CertificatesSet.
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function timestamp(string $digest): string
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->apiUrl . '/timestamp/' . $digest)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }

        return $this->json_decode($response->getBody()->getContents())['token'];
    }

    /**
     * Retrieve the validation policy associated with the calling account
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#validationpolicy_get
     * @return array Validation policy associated with the current account
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function getValidationPolicy(): array
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->apiUrl . '/validationpolicy')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }

        return $this->json_decode($response->getBody()->getContents());
    }

    /**
     * Query the chain of trust for the certificates issued by the calling account and the revocation info for the
     * certificates in the chain
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#trustchain_get
     * @return array
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function getTrustchain(): array
    {
        $request = (
            $this->requestFactory->createRequest('GET', $this->apiUrl . '/trustchain')
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }

        return $this->json_decode($response->getBody()->getContents());
    }

    /**
     * Query remaining quota of a specific type for the calling account.
     *
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#quotas_signatures_get
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#quotas_timestamps_get
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#quotas_users_get
     * @param string $type
     * @return int
     * @throws ClientExceptionInterface If an error happens while processing the request.
     * @throws UnexpectedResponseException
     */
    public function getQuota(string $type): int
    {
        if (!\in_array($type, [self::TYPE_SIGNATURES, self::TYPE_TIMESTAMPS, self::TYPE_USERS], true)) {
            throw new \InvalidArgumentException(sprintf('Unknow quota type: "%s".', $type));
        }

        $request = (
            $this->requestFactory->createRequest('GET', $this->apiUrl . '/quotas/' . $type)
            ->withHeader('Authorization', 'Bearer ' . $this->login())
        );

        $response = $this->httpClient->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedResponseException($response);
        }

        return (int) $this->json_decode((string) $response->getBody())['value'];
    }
}
