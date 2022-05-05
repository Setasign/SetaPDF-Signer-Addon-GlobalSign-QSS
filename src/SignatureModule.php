<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalSign\Qss;

use Psr\Http\Client\ClientExceptionInterface;
use SetaPDF_Signer_ValidationRelatedInfo_Collector;
use SetaPDF_Signer_X509_Collection;

/**
 * The signature module for the SetaPDF-Signer component
 */
class SignatureModule implements
    \SetaPDF_Signer_Signature_Module_ModuleInterface,
    \SetaPDF_Signer_Signature_DictionaryInterface,
    \SetaPDF_Signer_Signature_DocumentInterface
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * @var \SetaPDF_Signer_Signature_Module_Cms
     */
    protected $module;

    /**
     * @var string
     */
    protected $email;

    /**
     * @var bool
     */
    protected $addRevocationInfo = true;

    /**
     * @var array
     */
    protected $subjectDn = [];

    /**
     * @var null|string
     */
    protected $certificate;

    /**
     * @var null|string[]
     */
    protected $trustchain;

    /**
     * @var null|string[]
     */
    protected $ocspResponses;

    /**
     * The constructor.
     *
     * @param \SetaPDF_Signer $signer The main signer instance (used to disable the automatic change of the signature
     *                                length)
     * @param Client $client A REST client instance
     * @param string $email
     * @param \SetaPDF_Signer_Signature_Module_Cms $module An outer signature module instance which is used for CMS
     *                                                     creation while the signature value is created and set by this
     *                                                     class.
     */
    public function __construct(
        \SetaPDF_Signer $signer,
        Client $client,
        string $email,
        \SetaPDF_Signer_Signature_Module_Cms $module
    ){
        $signer->setAllowSignatureContentLengthChange(false);

        $this->client = $client;
        $this->email = $email;
        $this->module = $module;
    }

    /**
     * Define whether to add revocation information to the CMS container or not (default = true).
     *
     * @param bool $addRevocationInfo
     */
    public function setAddRevocationInfo(bool $addRevocationInfo)
    {
        $this->addRevocationInfo = $addRevocationInfo;
    }

    /**
     * @see https://www.globalsign.com/en/resources/apis/api-documentation/qss_api_v1.html#users__email__identity_post
     * @param array $subjectDn List of Distinguished Name attributes to include in the certificate. See RFC 5280#4.1.2.6
     * @return void
     */
    public function setSubjectDn(array $subjectDn)
    {
        $this->subjectDn = $subjectDn;
    }

    public function getCertificate(): string
    {
        return $this->certificate;
    }

    public function getTrustchain(): array
    {
        return $this->trustchain;
    }

    public function getOcspResponses(): array
    {
        return $this->ocspResponses;
    }

    /**
     * Create a signature for the file in the given $tmpPath.
     *
     * @param \SetaPDF_Core_Reader_FilePath $tmpPath
     * @return string
     * @throws Exception
     * @throws ClientExceptionInterface
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws \SetaPDF_Signer_Exception
     */
    public function createSignature(\SetaPDF_Core_Reader_FilePath $tmpPath): string
    {
        $identityResponse = $this->client->createUserIdentity($this->email, $this->subjectDn);
        $this->certificate = $identityResponse['signing_cert'];
        $this->module->setCertificate($identityResponse['signing_cert']);

        $trustchainResponse = $this->client->getTrustchain();
        $this->trustchain = $trustchainResponse['trustchain'];
        $this->module->setExtraCertificates($trustchainResponse['trustchain']);

        $this->ocspResponses = [
            \base64_decode($identityResponse['ocsp_response'])
        ];
        foreach ($trustchainResponse['ocsp_revocation_info'] as $ocspRevocationInfo) {
            $this->ocspResponses[] = \base64_decode($ocspRevocationInfo);
        }

        if ($this->addRevocationInfo) {
            foreach ($this->ocspResponses as $ocspResponse) {
                $this->module->addOcspResponse($ocspResponse);
            }
        }

        $hash = \hash('sha256', $this->module->getDataToSign($tmpPath));
        $signature = $this->client->sign($this->email, $hash);

        $this->module->setSignatureValue(\SetaPDF_Core_Type_HexString::hex2str($signature));

        return (string) $this->module->getCms();
    }

    /**
     * Method to update the signature dictionary.
     *
     * @param \SetaPDF_Core_Type_Dictionary $dictionary
     */
    public function updateSignatureDictionary(\SetaPDF_Core_Type_Dictionary $dictionary)
    {
        if ($this->module instanceof \SetaPDF_Signer_Signature_DictionaryInterface) {
            $this->module->updateSignatureDictionary($dictionary);
        }
    }

    /**
     * Method to allow updates onto the document instance.
     *
     * @param \SetaPDF_Core_Document $document
     */
    public function updateDocument(\SetaPDF_Core_Document $document)
    {
        if ($this->module instanceof \SetaPDF_Signer_Signature_DocumentInterface) {
            $this->module->updateDocument($document);
        }
    }
}