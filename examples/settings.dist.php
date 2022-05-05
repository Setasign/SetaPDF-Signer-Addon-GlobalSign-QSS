<?php

declare(strict_types=1);

return [
    'apiUrl' => 'https://emea.api.qss.globalsign.com:8443',
    'apiKey' => 'your-api-key',
    'apiSecret' => 'your-api-secret',
    // Set to a string to specify the path to a file containing a PEM formatted client side certificate.
    // If a password is required, then set to an array containing the path to the PEM file in the first array
    // element followed by the password required for the certificate in the second array element.
    'cert' => realpath(__DIR__ . '/private/mTLS-Cert.pem'),
    // Specify the path to a file containing a private SSL key in PEM format.
    // If a password is required, then set to an array containing the path to the SSL key in the first array element
    // followed by the password required for the certificate in the second element.
    'privateKey' => [realpath(__DIR__ . '/private/privatekey.pem'), 'your-private-key-password'],

    'email' => 'your-email',
];