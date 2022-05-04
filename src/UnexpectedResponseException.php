<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Qss;

use Psr\Http\Message\ResponseInterface;

class UnexpectedResponseException extends Exception
{
    public function __construct(ResponseInterface $response)
    {
        parent::__construct(\sprintf(
            'Unexpected response status code (%d). Response: %s',
            $response->getStatusCode(),
            $response->getBody()->getContents()
        ));
    }
}
