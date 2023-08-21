<?php

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\CurlHandler;
use Http\Factory\Guzzle\RequestFactory;
use Http\Factory\Guzzle\StreamFactory;
use Mjelamanov\GuzzlePsr18\Client as Psr18Wrapper;
use setasign\SetaPDF\Signer\Module\GlobalSign\Qss\Client;
use setasign\SetaPDF\Signer\Module\GlobalSign\Qss\SignatureModule;
use setasign\SetaPDF\Signer\Module\GlobalSign\Qss\TimestampModule;

date_default_timezone_set('Europe/Berlin');
error_reporting(E_ALL | E_STRICT);
ini_set('display_errors', '1');

require_once __DIR__ . '/../vendor/autoload.php';

if (!file_exists(__DIR__ . '/settings.php')) {
    throw new RuntimeException('Missing settings.php!');
}
$settings = require __DIR__ . '/settings.php';

$file = __DIR__ . '/assets/Laboratory-Report.pdf';

$httpClient = new GuzzleClient([
    'handler' => new CurlHandler(),
    // note: guzzle requires this parameter to fully support PSR-18
    'http_errors' => false,
    'cert' => $settings['cert'],
    'ssl_key' => $settings['privateKey']
]);
// only required if you are using guzzle < 7
$httpClient = new Psr18Wrapper($httpClient);
$requestFactory = new RequestFactory();
$streamFactory = new StreamFactory();

$client = new Client(
    $httpClient,
    $requestFactory,
    $streamFactory,
    $settings['apiKey'],
    $settings['apiSecret'],
    $settings['apiUrl']
);

// note: you have to create the user first and connect your app to it
//var_dump($client->createUser($settings['email'], 'Given name', 'Surname', '0049123456789'));
//var_dump($client->deleteUser($settings['email'])); // if you need to delete the user
//var_dump($client->getUser($settings['email'])); // if you need to get the data (e.g. the id) of the user
//die();

$reader = new SetaPDF_Core_Reader_File($file);
// create a writer instance
$writer = new SetaPDF_Core_Writer_File(__DIR__ . '/signed.pdf');
$tmpWriter = new SetaPDF_Core_Writer_TempFile();
// let's get the document
$document = SetaPDF_Core_Document::load($reader, $tmpWriter);

// now let's create a signer instance
$signer = new SetaPDF_Signer($document);

$tsModule = new TimestampModule($client);
$signer->setTimestampModule($tsModule);

// set some signature properties
$signer->setReason('Testing GlobalSign QSS');

$module = new SignatureModule($signer, $client, $settings['email'], new SetaPDF_Signer_Signature_Module_Pades());

$signatureField = $signer->getSignatureField();
$signer->setSignatureFieldName($signatureField->getQualifiedName());

$signer->sign($module);


// create a new instance
$document = SetaPDF_Core_Document::loadByFilename($tmpWriter->getPath(), $writer);

// and add it to the document.
$dss = new SetaPDF_Signer_DocumentSecurityStore($document);
$dss->addValidationRelatedInfoByFieldName(
    $signatureField->getQualifiedName(),
    [],
    $module->getOcspResponses(),
    $module->getTrustchain()
);

// save and finish the final document
$document->save()->finish();
