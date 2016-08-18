# dss-validator-cli
Command line interface for playing around with the DSS-Framework PDF validator settings.

The following parameters can be modified for single or multiple PDF documents:
<ul>
<li>Validation policy</li>
<li>Report output formats</li>
<li>Build trust-store from DER encoded certificate files stored in a directory and/or database</li>
</ul>

### DSS-Framework
The validation process is based on the DSS-Framework (https://github.com/esig/dss).

## Validator usage:

-c,--certs <DIRECTORY> directory containing certificates for validation. If no certificates are provided,no certificate is used for validation.
-db,--database Certificates are loaded from the database specified in db.config.properties
-f,--file <PDF-FILE> The PDF file to validate. If a directory is provided, the application will search for documents and validate them.
-h,--help Shows this help dialog
-p,--policy <XML-FILE> DSS Validation Policy (XML Format). If not defined, the default policy is used.
-rd,--rdest <DIRECTORY> Destination for output file. If not defined, the output directory containing the PDF file is used.
-rf,--rformat <ATTRIBUTE> Report format. Multiple formats must be provided comma-separated without whitespace. Possible attributes: std (default), detail, diagnostic.
