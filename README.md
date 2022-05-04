# SetaPDF-Signer component modules for the GlobalSign Qualified Signing Service.

This package offers modules for the [SetaPDF-Signer](https://www.setasign.com/signer) component that allow you
to use the Qualified Signing Service by
[GlobalSign](https://www.globalsign.com) to **digital sign and timestamp with qualified signatures PDF documents in pure PHP**.

## Requirements

To use this package you need credentials for the GlobalSign Qualified Signing Service which are:

1. Your private key
2. Client certificate for mTLS connection to the API
3. Your API key and password
4. [the QSS Mobile App](https://media.globalsign.com/how-to-use-qss-mobile-app)

This package is developed and tested on PHP >= 7.1. Requirements of the [SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

We're using [PSR-17 (HTTP Factories)](https://www.php-fig.org/psr/psr-17/) and
[PSR-18 (HTTP Client)](https://www.php-fig.org/psr/psr-18/) for the requests. So you'll need an implementation of
these. We recommend using Guzzle.

### For PHP 7.1
```
    "require" : {
        "guzzlehttp/guzzle": "^6.5",
        "http-interop/http-factory-guzzle": "^1.0",
        "mjelamanov/psr18-guzzle": "^1.3"
    }
```

### For >= PHP 7.2
```
    "require" : {
        "guzzlehttp/guzzle": "^7.0",
        "http-interop/http-factory-guzzle": "^1.0"
    }
```

## Installation
Add following to your composer.json:

```json
{
    "require": {
        "setasign/seta-pdf-signer-addon-global-sign-qss": "^1.0"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to evaluate the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component (see
[here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

### Trial version
By default, this packages depends on a licensed version of the [SetaPDF-Signer](https://www.setasign.com/signer) component.
If you want to use it with an evaluation version please use following in your composer.json:

```json
{
    "require": {
        "setasign/seta-pdf-signer-addon-global-sign-qss": "dev-trial"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
