SOPS: Secrets OPerationS
========================

**SOPS** is an editor of encrypted files that supports YAML, JSON, ENV, INI and BINARY
formats and encrypts with AWS KMS, GCP KMS, Azure Key Vault, age, and PGP.
(`demo <https://www.youtube.com/watch?v=YTEVyLXFiq0>`_)

.. image:: https://i.imgur.com/X0TM5NI.gif

------------

.. image:: https://pkg.go.dev/badge/github.com/getsops/sops/v3.svg
    :target: https://pkg.go.dev/github.com/getsops/sops/v3

Download
--------

Stable release
~~~~~~~~~~~~~~
Binaries and packages of the latest stable release are available at `https://github.com/getsops/sops/releases <https://github.com/getsops/sops/releases>`_.

Development branch
~~~~~~~~~~~~~~~~~~
For the adventurous, unstable features are available in the `main` branch, which you can install from source:

.. code:: bash

    $ mkdir -p $GOPATH/src/github.com/getsops/sops/
    $ git clone https://github.com/getsops/sops.git $GOPATH/src/github.com/getsops/sops/
    $ cd $GOPATH/src/github.com/getsops/sops/
    $ make install

(requires Go >= 1.19)

If you don't have Go installed, set it up with:

.. code:: bash

    $ {apt,yum,brew} install golang
    $ echo 'export GOPATH=~/go' >> ~/.bashrc
    $ source ~/.bashrc
    $ mkdir $GOPATH

Or whatever variation of the above fits your system and shell.

To use **SOPS** as a library, take a look at the `decrypt package <https://pkg.go.dev/github.com/getsops/sops/v3/decrypt>`_.

.. sectnum::
.. contents:: Table of Contents

Usage
-----

For a quick presentation of SOPS, check out this Youtube tutorial:

.. image:: https://img.youtube.com/vi/V2PRhxphH2w/0.jpg
   :target: https://www.youtube.com/watch?v=V2PRhxphH2w

If you're using AWS KMS, create one or multiple master keys in the IAM console
and export them, comma separated, in the **SOPS_KMS_ARN** env variable. It is
recommended to use at least two master keys in different regions.

.. code:: bash

    export SOPS_KMS_ARN="arn:aws:kms:us-east-1:656532927350:key/920aff2e-c5f1-4040-943a-047fa387b27e,arn:aws:kms:ap-southeast-1:656532927350:key/9006a8aa-0fa6-4c14-930e-a2dfb916de1d"

SOPS uses `aws-sdk-go-v2 <https://github.com/aws/aws-sdk-go-v2>`_ to communicate with AWS KMS. It will automatically
read the credentials from the ``~/.aws/credentials`` file which can be created with the ``aws configure`` command.

An example of the ``~/.aws/credentials`` file is shown below:

.. code:: sh

    $ cat ~/.aws/credentials
    [default]
    aws_access_key_id = AKI.....
    aws_secret_access_key = mw......

In addition to the ``~/.aws/credentials`` file, you can also use the ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY``
environment variables to specify your credentials:

.. code:: bash

    export AWS_ACCESS_KEY_ID="AKI......"
    export AWS_SECRET_ACCESS_KEY="mw......"

For more information and additional environment variables, see
`specifying credentials <https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/#specifying-credentials>`_.

If you want to use PGP, export the fingerprints of the public keys, comma
separated, in the **SOPS_PGP_FP** env variable.

.. code:: bash

    export SOPS_PGP_FP="85D77543B3D624B63CEA9E6DBC17301B491B3F21,E60892BB9BD89A69F759A1A0A3D652173B763E8F"

Note: you can use both PGP and KMS simultaneously.

Then simply call ``sops edit`` with a file path as argument. It will handle the
encryption/decryption transparently and open the cleartext file in an editor

.. code:: sh

    $ sops edit mynewtestfile.yaml
    mynewtestfile.yaml doesn't exist, creating it.
    please wait while an encryption key is being generated and stored in a secure fashion
    file written to mynewtestfile.yaml

Editing will happen in whatever ``$EDITOR`` is set to, or, if it's not set, in vim.
Keep in mind that SOPS will wait for the editor to exit, and then try to reencrypt
the file. Some GUI editors (atom, sublime) spawn a child process and then exit
immediately. They usually have an option to wait for the main editor window to be
closed before exiting. See `#127 <https://github.com/getsops/sops/issues/127>`_ for
more information.

The resulting encrypted file looks like this:

.. code:: yaml

    myapp1: ENC[AES256_GCM,data:Tr7o=,iv:1=,aad:No=,tag:k=]
    app2:
        db:
            user: ENC[AES256_GCM,data:CwE4O1s=,iv:2k=,aad:o=,tag:w==]
            password: ENC[AES256_GCM,data:p673w==,iv:YY=,aad:UQ=,tag:A=]
        # private key for secret operations in app2
        key: |-
            ENC[AES256_GCM,data:Ea3kL5O5U8=,iv:DM=,aad:FKA=,tag:EA==]
    an_array:
        - ENC[AES256_GCM,data:v8jQ=,iv:HBE=,aad:21c=,tag:gA==]
        - ENC[AES256_GCM,data:X10=,iv:o8=,aad:CQ=,tag:Hw==]
        - ENC[AES256_GCM,data:KN=,iv:160=,aad:fI4=,tag:tNw==]
    sops:
        kms:
            - created_at: 1441570389.775376
              enc: CiC....Pm1Hm
              arn: arn:aws:kms:us-east-1:656532927350:key/920aff2e-c5f1-4040-943a-047fa387b27e
            - created_at: 1441570391.925734
              enc: Ci...awNx
              arn: arn:aws:kms:ap-southeast-1:656532927350:key/9006a8aa-0fa6-4c14-930e-a2dfb916de1d
        pgp:
            - fp: 85D77543B3D624B63CEA9E6DBC17301B491B3F21
              created_at: 1441570391.930042
              enc: |
                  -----BEGIN PGP MESSAGE-----
                  hQIMA0t4uZHfl9qgAQ//UvGAwGePyHuf2/zayWcloGaDs0MzI+zw6CmXvMRNPUsA
                  ...=oJgS
                  -----END PGP MESSAGE-----

A copy of the encryption/decryption key is stored securely in each KMS and PGP
block. As long as one of the KMS or PGP method is still usable, you will be able
to access your data.

To decrypt a file in a ``cat`` fashion, use the ``-d`` flag:

.. code:: sh

    $ sops decrypt mynewtestfile.yaml

SOPS encrypted files contain the necessary information to decrypt their content.
All a user of SOPS needs is valid AWS credentials and the necessary
permissions on KMS keys.

Given that, the only command a SOPS user needs is:

.. code:: sh

    $ sops edit <file>

`<file>` will be opened, decrypted, passed to a text editor (vim by default),
encrypted if modified, and saved back to its original location. All of these
steps, apart from the actual editing, are transparent to the user.

The order in which available decryption methods are tried can be specified with
``--decryption-order`` option or **SOPS_DECRYPTION_ORDER** environment variable
as a comma separated list. The default order is ``age,pgp``. Offline methods are
tried first and then the remaining ones.

Test with the dev PGP key
~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to test **SOPS** without having to do a bunch of setup, you can use
the example files and pgp key provided with the repository::

    $ git clone https://github.com/getsops/sops.git
    $ cd sops
    $ gpg --import pgp/sops_functional_tests_key.asc
    $ sops edit example.yaml

This last step will decrypt ``example.yaml`` using the test private key.


Encrypting using age
~~~~~~~~~~~~~~~~~~~~

`age <https://age-encryption.org/>`_ is a simple, modern, and secure tool for
encrypting files. It's recommended to use age over PGP, if possible.

You can encrypt a file for one or more age recipients (comma separated) using
the ``--age`` option or the **SOPS_AGE_RECIPIENTS** environment variable:

.. code:: sh

    $ sops encrypt --age age1yt3tfqlfrwdwx0z0ynwplcr6qxcxfaqycuprpmy89nr83ltx74tqdpszlw test.yaml > test.enc.yaml

When decrypting a file with the corresponding identity, SOPS will look for a
text file name ``keys.txt`` located in a ``sops`` subdirectory of your user
configuration directory. On Linux, this would be ``$XDG_CONFIG_HOME/sops/age/keys.txt``.
On macOS, this would be ``$HOME/Library/Application Support/sops/age/keys.txt``. On
Windows, this would be ``%AppData%\sops\age\keys.txt``. You can specify the location
of this file manually by setting the environment variable **SOPS_AGE_KEY_FILE**.
Alternatively, you can provide the key(s) directly by setting the **SOPS_AGE_KEY**
environment variable.

The contents of this key file should be a list of age X25519 identities, one
per line. Lines beginning with ``#`` are considered comments and ignored. Each
identity will be tried in sequence until one is able to decrypt the data.

Encrypting with SSH keys via age is not yet supported by SOPS.


Encrypting using GCP KMS
~~~~~~~~~~~~~~~~~~~~~~~~
GCP KMS uses `Application Default Credentials
<https://developers.google.com/identity/protocols/application-default-credentials>`_.
If you already logged in using

.. code:: sh

    $ gcloud auth login

you can enable application default credentials using the sdk:

.. code:: sh

    $ gcloud auth application-default login

Encrypting/decrypting with GCP KMS requires a KMS ResourceID. You can use the
cloud console the get the ResourceID or you can create one using the gcloud
sdk:

.. code:: sh

    $ gcloud kms keyrings create sops --location global
    $ gcloud kms keys create sops-key --location global --keyring sops --purpose encryption
    $ gcloud kms keys list --location global --keyring sops

    # you should see
    NAME                                                                   PURPOSE          PRIMARY_STATE
    projects/my-project/locations/global/keyRings/sops/cryptoKeys/sops-key ENCRYPT_DECRYPT  ENABLED

Now you can encrypt a file using::

    $ sops encrypt --gcp-kms projects/my-project/locations/global/keyRings/sops/cryptoKeys/sops-key test.yaml > test.enc.yaml

And decrypt it using::

     $ sops decrypt test.enc.yaml

Encrypting using Azure Key Vault
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Azure Key Vault integration uses the
`default credential chain <https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#DefaultAzureCredential>`_
which tries several authentication methods, in this order:

1. `Environment credentials <https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#EnvironmentCredential>`_

   i. Service Principal with Client Secret
   ii. Service Principal with Certificate
   iii. User with username and password
   iv. Configuration for multi-tenant applications

2. `Workload Identity credentials <https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#WorkloadIdentityCredential>`_
3. `Managed Identity credentials <https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#ManagedIdentityCredential>`_
4. `Azure CLI credentials <https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#AzureCLICredential>`_

For example, you can use a Service Principal with the following environment variables:

.. code:: bash

    AZURE_TENANT_ID
    AZURE_CLIENT_ID
    AZURE_CLIENT_SECRET

You can create a Service Principal using the CLI like this:

.. code:: sh

    $ az ad sp create-for-rbac -n my-keyvault-sp

    {
        "appId": "<some-uuid>",
        "displayName": "my-keyvault-sp",
        "name": "http://my-keyvault-sp",
        "password": "<random-string>",
        "tenant": "<tenant-uuid>"
    }

The `appId` is the client ID, and the `password` is the client secret.

Encrypting/decrypting with Azure Key Vault requires the resource identifier for
a key. This has the following form::

    https://${VAULT_URL}/keys/${KEY_NAME}/${KEY_VERSION}

To create a Key Vault and assign your service principal permissions on it
from the commandline:

.. code:: sh

    # Create a resource group if you do not have one:
    $ az group create --name sops-rg --location westeurope
    # Key Vault names are globally unique, so generate one:
    $ keyvault_name=sops-$(uuidgen | tr -d - | head -c 16)
    # Create a Vault, a key, and give the service principal access:
    $ az keyvault create --name $keyvault_name --resource-group sops-rg --location westeurope
    $ az keyvault key create --name sops-key --vault-name $keyvault_name --protection software --ops encrypt decrypt
    $ az keyvault set-policy --name $keyvault_name --resource-group sops-rg --spn $AZURE_CLIENT_ID \
        --key-permissions encrypt decrypt
    # Read the key id:
    $ az keyvault key show --name sops-key --vault-name $keyvault_name --query key.kid

    https://sops.vault.azure.net/keys/sops-key/some-string

Now you can encrypt a file using::

    $ sops encrypt --azure-kv https://sops.vault.azure.net/keys/sops-key/some-string test.yaml > test.enc.yaml

And decrypt it using::

    $ sops decrypt test.enc.yaml


Encrypting and decrypting from other programs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using ``sops`` in scripts or from other programs, there are often situations where you do not want to write
encrypted or decrypted data to disk. The best way to avoid this is to pass data to SOPS via stdin, and to let
SOPS write data to stdout. By default, the encrypt and decrypt operations write data to stdout already. To pass
data via stdin, you need to pass ``/dev/stdin`` as the input filename. Please note that this only works on
Unix-like operating systems such as macOS and Linux. On Windows, you have to use named pipes.

To decrypt data, you can simply do:

.. code:: sh

	$ cat encrypted-data | sops decrypt /dev/stdin > decrypted-data

To control the input and output format, pass ``--input-type`` and ``--output-type`` as appropriate. By default,
``sops`` determines the input and output format from the provided filename, which is ``/dev/stdin`` here, and
thus will use the binary store which expects JSON input and outputs binary data on decryption.

For example, to decrypt YAML data and obtain the decrypted result as YAML, use:

.. code:: sh

	$ cat encrypted-data | sops decrypt --input-type yaml --output-type yaml /dev/stdin > decrypted-data

To encrypt, it is important to note that SOPS also uses the filename to look up the correct creation rule from
``.sops.yaml``. Likely ``/dev/stdin`` will not match a creation rule, or only match the fallback rule without
``path_regex``, which is usually not what you want. For that, ``sops`` provides the ``--filename-override``
parameter which allows you to tell SOPS which filename to use to match creation rules:

.. code:: sh

	$ echo 'foo: bar' | sops encrypt --filename-override path/filename.sops.yaml /dev/stdin > encrypted-data

SOPS will find a matching creation rule for ``path/filename.sops.yaml`` in ``.sops.yaml`` and use that one to
encrypt the data from stdin. This filename will also be used to determine the input and output store. As always,
the input store type can be adjusted by passing ``--input-type``, and the output store type by passing
``--output-type``:

.. code:: sh

	$ echo foo=bar | sops encrypt --filename-override path/filename.sops.yaml --input-type dotenv /dev/stdin > encrypted-data


Encrypting using Hashicorp Vault
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We assume you have an instance (or more) of Vault running and you have privileged access to it. For instructions on how to deploy a secure instance of Vault, refer to Hashicorp's official documentation.

To easily deploy Vault locally: (DO NOT DO THIS FOR PRODUCTION!!!) 

.. code:: sh

    $ docker run -d -p8200:8200 vault:1.2.0 server -dev -dev-root-token-id=toor


.. code:: sh

    $ # Substitute this with the address Vault is running on
    $ export VAULT_ADDR=http://127.0.0.1:8200 

    $ # this may not be necessary in case you previously used `vault login` for production use
    $ export VAULT_TOKEN=toor 
    
    $ # to check if Vault started and is configured correctly
    $ vault status
    Key             Value
    ---             -----
    Seal Type       shamir
    Initialized     true
    Sealed          false
    Total Shares    1
    Threshold       1
    Version         1.2.0
    Cluster Name    vault-cluster-618cc902
    Cluster ID      e532e461-e8f0-1352-8a41-fc7c11096908
    HA Enabled      false

    $ # It is required to enable a transit engine if not already done (It is suggested to create a transit engine specifically for SOPS, in which it is possible to have multiple keys with various permission levels)
    $ vault secrets enable -path=sops transit
    Success! Enabled the transit secrets engine at: sops/

    $ # Then create one or more keys
    $ vault write sops/keys/firstkey type=rsa-4096
    Success! Data written to: sops/keys/firstkey

    $ vault write sops/keys/secondkey type=rsa-2048
    Success! Data written to: sops/keys/secondkey

    $ vault write sops/keys/thirdkey type=chacha20-poly1305
    Success! Data written to: sops/keys/thirdkey

    $ sops encrypt --hc-vault-transit $VAULT_ADDR/v1/sops/keys/firstkey vault_example.yml

    $ cat <<EOF > .sops.yaml
    creation_rules:
        - path_regex: \.dev\.yaml$
          hc_vault_transit_uri: "$VAULT_ADDR/v1/sops/keys/secondkey"
        - path_regex: \.prod\.yaml$
          hc_vault_transit_uri: "$VAULT_ADDR/v1/sops/keys/thirdkey"
    EOF

    $ sops encrypt --verbose prod/raw.yaml > prod/encrypted.yaml

Adding and removing keys
~~~~~~~~~~~~~~~~~~~~~~~~

When creating new files, ``sops`` uses the PGP, KMS and GCP KMS defined in the
command line arguments ``--kms``, ``--pgp``, ``--gcp-kms`` or ``--azure-kv``, or from
the environment variables ``SOPS_KMS_ARN``, ``SOPS_PGP_FP``, ``SOPS_GCP_KMS_IDS``,
``SOPS_AZURE_KEYVAULT_URLS``. That information is stored in the file under the
``sops`` section, such that decrypting files does not require providing those
parameters again.

Master PGP and KMS keys can be added and removed from a ``sops`` file in one of
three ways:

1. By using a ``.sops.yaml`` file and the ``updatekeys`` command.

2. By using command line flags.

3. By editing the file directly.

The SOPS team recommends the ``updatekeys`` approach.


``updatekeys`` command
**********************

The ``updatekeys`` command uses the `.sops.yaml <#using-sops-yaml-conf-to-select-kms-pgp-for-new-files>`_
configuration file to update (add or remove) the corresponding secrets in the
encrypted file. Note that the example below uses the
`Block Scalar yaml construct <https://yaml-multiline.info/>`_ to build a space
separated list.

.. code:: yaml

    creation_rules:
        - pgp: >-
            85D77543B3D624B63CEA9E6DBC17301B491B3F21,
            FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4

.. code:: sh

    $ sops updatekeys test.enc.yaml

SOPS will prompt you with the changes to be made. This interactivity can be
disabled by supplying the ``-y`` flag.

``rotate`` command
******************

The ``rotate`` command generates a new data encryption key and reencrypt all values
with the new key. At te same time, the command line flag ``--add-kms``, ``--add-pgp``,
``--add-gcp-kms``, ``--add-azure-kv``, ``--rm-kms``, ``--rm-pgp``, ``--rm-gcp-kms``
and ``--rm-azure-kv`` can be used to add and remove keys from a file. These flags use
the comma separated syntax as the ``--kms``, ``--pgp``, ``--gcp-kms`` and ``--azure-kv``
arguments when creating new files.

Use ``updatekeys`` if you want to add a key without rotating the data key.

.. code:: sh

    # add a new pgp key to the file and rotate the data key
    $ sops rotate -i --add-pgp 85D77543B3D624B63CEA9E6DBC17301B491B3F21 example.yaml

    # remove a pgp key from the file and rotate the data key
    $ sops rotate -i --rm-pgp 85D77543B3D624B63CEA9E6DBC17301B491B3F21 example.yaml


Direct Editing
**************

Alternatively, invoking ``sops edit`` with the flag **-s** will display the master keys
while editing. This method can be used to add or remove ``kms`` or ``pgp`` keys under the
``sops`` section.

For example, to add a KMS master key to a file, add the following entry while
editing:

.. code:: yaml

    sops:
        kms:
            - arn: arn:aws:kms:us-east-1:656532927350:key/920aff2e-c5f1-4040-943a-047fa387b27e

And, similarly, to add a PGP master key, we add its fingerprint:

.. code:: yaml

    sops:
        pgp:
            - fp: 85D77543B3D624B63CEA9E6DBC17301B491B3F21

When the file is saved, SOPS will update its metadata and encrypt the data key
with the freshly added master keys. The removed entries are simply deleted from
the file.

When removing keys, it is recommended to rotate the data key using ``-r``,
otherwise, owners of the removed key may have add access to the data key in the
past.

KMS AWS Profiles
~~~~~~~~~~~~~~~~

If you want to use a specific profile, you can do so with `aws_profile`:

.. code:: yaml

    sops:
        kms:
            - arn: arn:aws:kms:us-east-1:656532927350:key/920aff2e-c5f1-4040-943a-047fa387b27e
              aws_profile: foo

If no AWS profile is set, default credentials will be used.

Similarly the `--aws-profile` flag can be set with the command line with any of the KMS commands.


Assuming roles and using KMS in various AWS accounts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SOPS has the ability to use KMS in multiple AWS accounts by assuming roles in
each account. Being able to assume roles is a nice feature of AWS that allows
administrators to establish trust relationships between accounts, typically from
the most secure account to the least secure one. In our use-case, we use roles
to indicate that a user of the Master AWS account is allowed to make use of KMS
master keys in development and staging AWS accounts. Using roles, a single file
can be encrypted with KMS keys in multiple accounts, thus increasing reliability
and ease of use.

You can use keys in various accounts by tying each KMS master key to a role that
the user is allowed to assume in each account. The `IAM roles
<http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html>`_
documentation has full details on how this needs to be configured on AWS's side.

From the point of view of SOPS, you only need to specify the role a KMS key
must assume alongside its ARN, as follows:

.. code:: yaml

    sops:
        kms:
            - arn: arn:aws:kms:us-east-1:656532927350:key/920aff2e-c5f1-4040-943a-047fa387b27e
              role: arn:aws:iam::927034868273:role/sops-dev-xyz

The role must have permission to call Encrypt and Decrypt using KMS. An example
policy is shown below.

.. code:: json

    {
      "Sid": "Allow use of the key",
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Principal": {
        "AWS": [
          "arn:aws:iam::927034868273:role/sops-dev-xyz"
        ]
      }
    }

You can specify a role in the ``--kms`` flag and ``SOPS_KMS_ARN`` variable by
appending it to the ARN of the master key, separated by a **+** sign::

    <KMS ARN>+<ROLE ARN>
    arn:aws:kms:us-west-2:927034868273:key/fe86dd69-4132-404c-ab86-4269956b4500+arn:aws:iam::927034868273:role/sops-dev-xyz

AWS KMS Encryption Context
~~~~~~~~~~~~~~~~~~~~~~~~~~

SOPS has the ability to use `AWS KMS key policy and encryption context
<http://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html>`_
to refine the access control of a given KMS master key.

When creating a new file, you can specify the encryption context in the
``--encryption-context`` flag by comma separated list of key-value pairs:

.. code:: sh

    $ sops edit --encryption-context Environment:production,Role:web-server test.dev.yaml

The format of the Encrypt Context string is ``<EncryptionContext Key>:<EncryptionContext Value>,<EncryptionContext Key>:<EncryptionContext Value>,...``

The encryption context will be stored in the file metadata and does
not need to be provided at decryption.

Encryption contexts can be used in conjunction with KMS Key Policies to define
roles that can only access a given context. An example policy is shown below:

.. code:: json

    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/RoleForExampleApp"
      },
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:EncryptionContext:AppName": "ExampleApp",
          "kms:EncryptionContext:FilePath": "/var/opt/secrets/"
        }
      }
    }

Key Rotation
~~~~~~~~~~~~

It is recommended to renew the data key on a regular basis. ``sops`` supports key
rotation via the ``rotate`` command. Invoking it on an existing file causes ``sops``
to reencrypt the file with a new data key, which is then encrypted with the various
KMS and PGP master keys defined in the file.

Add the ``-i`` option to write the rotated file back, instead of printing it to
stdout.

.. code:: sh

    $ sops rotate example.yaml

Using .sops.yaml conf to select KMS, PGP and age for new files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is often tedious to specify the ``--kms`` ``--gcp-kms`` ``--pgp`` and ``--age`` parameters for creation
of all new files. If your secrets are stored under a specific directory, like a
``git`` repository, you can create a ``.sops.yaml`` configuration file at the root
directory to define which keys are used for which filename.

Let's take an example:

* file named **something.dev.yaml** should use one set of KMS A, PGP and age
* file named **something.prod.yaml** should use another set of KMS B, PGP and age
* other files use a third set of KMS C and PGP
* all live under **mysecretrepo/something.{dev,prod,gcp}.yaml**

Under those circumstances, a file placed at **mysecretrepo/.sops.yaml**
can manage the three sets of configurations for the three types of files:

.. code:: yaml

    # creation rules are evaluated sequentially, the first match wins
    creation_rules:
        # upon creation of a file that matches the pattern *.dev.yaml,
        # KMS set A as well as PGP and age is used
        - path_regex: \.dev\.yaml$
          kms: 'arn:aws:kms:us-west-2:927034868273:key/fe86dd69-4132-404c-ab86-4269956b4500,arn:aws:kms:us-west-2:361527076523:key/5052f06a-5d3f-489e-b86c-57201e06f31e+arn:aws:iam::361527076523:role/hiera-sops-prod'
          pgp: 'FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4'
          age: 'age129h70qwx39k7h5x6l9hg566nwm53527zvamre8vep9e3plsm44uqgy8gla'

        # prod files use KMS set B in the PROD IAM, PGP and age
        - path_regex: \.prod\.yaml$
          kms: 'arn:aws:kms:us-west-2:361527076523:key/5052f06a-5d3f-489e-b86c-57201e06f31e+arn:aws:iam::361527076523:role/hiera-sops-prod,arn:aws:kms:eu-central-1:361527076523:key/cb1fab90-8d17-42a1-a9d8-334968904f94+arn:aws:iam::361527076523:role/hiera-sops-prod'
          pgp: 'FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4'
          age: 'age129h70qwx39k7h5x6l9hg566nwm53527zvamre8vep9e3plsm44uqgy8gla'
          hc_vault_uris: "http://localhost:8200/v1/sops/keys/thirdkey"

        # gcp files using GCP KMS
        - path_regex: \.gcp\.yaml$
          gcp_kms: projects/mygcproject/locations/global/keyRings/mykeyring/cryptoKeys/thekey

        # Finally, if the rules above have not matched, this one is a
        # catchall that will encrypt the file using KMS set C as well as PGP
        # The absence of a path_regex means it will match everything
        - kms: 'arn:aws:kms:us-west-2:927034868273:key/fe86dd69-4132-404c-ab86-4269956b4500,arn:aws:kms:us-west-2:142069644989:key/846cfb17-373d-49b9-8baf-f36b04512e47,arn:aws:kms:us-west-2:361527076523:key/5052f06a-5d3f-489e-b86c-57201e06f31e'
          pgp: 'FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4'

When creating any file under **mysecretrepo**, whether at the root or under
a subdirectory, SOPS will recursively look for a ``.sops.yaml`` file. If one is
found, the filename of the file being created is compared with the filename
regexes of the configuration file. The first regex that matches is selected,
and its KMS and PGP keys are used to encrypt the file. It should be noted that
the looking up of ``.sops.yaml`` is from the working directory (CWD) instead of
the directory of the encrypting file (see `Issue 242 <https://github.com/getsops/sops/issues/242>`_).

The ``path_regex`` checks the path of the encrypting file relative to the ``.sops.yaml`` config file. Here is another example:

* files located under directory **development** should use one set of KMS A
* files located under directory **production** should use another set of KMS B
* other files use a third set of KMS C

.. code:: yaml

    creation_rules:
        # upon creation of a file under development,
        # KMS set A is used
        - path_regex: .*/development/.*
          kms: 'arn:aws:kms:us-west-2:927034868273:key/fe86dd69-4132-404c-ab86-4269956b4500,arn:aws:kms:us-west-2:361527076523:key/5052f06a-5d3f-489e-b86c-57201e06f31e+arn:aws:iam::361527076523:role/hiera-sops-prod'
          pgp: 'FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4'

        # prod files use KMS set B in the PROD IAM
        - path_regex: .*/production/.*
          kms: 'arn:aws:kms:us-west-2:361527076523:key/5052f06a-5d3f-489e-b86c-57201e06f31e+arn:aws:iam::361527076523:role/hiera-sops-prod,arn:aws:kms:eu-central-1:361527076523:key/cb1fab90-8d17-42a1-a9d8-334968904f94+arn:aws:iam::361527076523:role/hiera-sops-prod'
          pgp: 'FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4'

        # other files use KMS set C
        - kms: 'arn:aws:kms:us-west-2:927034868273:key/fe86dd69-4132-404c-ab86-4269956b4500,arn:aws:kms:us-west-2:142069644989:key/846cfb17-373d-49b9-8baf-f36b04512e47,arn:aws:kms:us-west-2:361527076523:key/5052f06a-5d3f-489e-b86c-57201e06f31e'
          pgp: 'FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4'

Creating a new file with the right keys is now as simple as

.. code:: sh

    $ sops edit <newfile>.prod.yaml

Note that the configuration file is ignored when KMS or PGP parameters are
passed on the SOPS command line or in environment variables.

Specify a different GPG executable
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SOPS checks for the ``SOPS_GPG_EXEC`` environment variable. If specified,
it will attempt to use the executable set there instead of the default
of ``gpg``.

Example: place the following in your ``~/.bashrc``

.. code:: bash

    SOPS_GPG_EXEC = 'your_gpg_client_wrapper'


Specify a different GPG key server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, SOPS uses the key server ``keys.openpgp.org`` to retrieve the GPG
keys that are not present in the local keyring.
This is no longer configurable. You can learn more about why from this write-up: `SKS Keyserver Network Under Attack <https://gist.github.com/rjhansen/67ab921ffb4084c865b3618d6955275f>`_.


Key groups
~~~~~~~~~~

By default, SOPS encrypts the data key for a file with each of the master keys,
such that if any of the master keys is available, the file can be decrypted.
However, it is sometimes desirable to require access to multiple master keys
in order to decrypt files. This can be achieved with key groups.

When using key groups in SOPS, data keys are split into parts such that keys from
multiple groups are required to decrypt a file. SOPS uses Shamir's Secret Sharing
to split the data key such that each key group has a fragment, each key in the
key group can decrypt that fragment, and a configurable number of fragments (threshold)
are needed to decrypt and piece together the complete data key. When decrypting a
file using multiple key groups, SOPS goes through key groups in order, and in
each group, tries to recover the fragment of the data key using a master key from
that group. Once the fragment is recovered, SOPS moves on to the next group,
until enough fragments have been recovered to obtain the complete data key.

By default, the threshold is set to the number of key groups. For example, if
you have three key groups configured in your SOPS file and you don't override
the default threshold, then one master key from each of the three groups will
be required to decrypt the file.

Management of key groups is done with the ``sops groups`` command.

For example, you can add a new key group with 3 PGP keys and 3 KMS keys to the
file ``my_file.yaml``:

.. code:: sh

    $ sops groups add --file my_file.yaml --pgp fingerprint1 --pgp fingerprint2 --pgp fingerprint3 --kms arn1 --kms arn2 --kms arn3

Or you can delete the 1st group (group number 0, as groups are zero-indexed)
from ``my_file.yaml``:

.. code:: sh

    $ sops groups delete --file my_file.yaml 0

Key groups can also be specified in the ``.sops.yaml`` config file,
like so:

.. code:: yaml

    creation_rules:
        - path_regex: .*keygroups.*
          key_groups:
              # First key group
              - pgp:
                    - fingerprint1
                    - fingerprint2
                kms:
                    - arn: arn1
                      role: role1
                      context:
                          foo: bar
                    - arn: arn2
                      aws_profile: myprofile
              # Second key group
              - pgp:
                    - fingerprint3
                    - fingerprint4
                kms:
                    - arn: arn3
                    - arn: arn4
              # Third key group
              - pgp:
                    - fingerprint5

Given this configuration, we can create a new encrypted file like we normally
would, and optionally provide the ``--shamir-secret-sharing-threshold`` command line
flag if we want to override the default threshold. SOPS will then split the data
key into three parts (from the number of key groups) and encrypt each fragment with
the master keys found in each group.

For example:

.. code:: sh

    $ sops edit --shamir-secret-sharing-threshold 2 example.json

Alternatively, you can configure the Shamir threshold for each creation rule in the ``.sops.yaml`` config
with ``shamir_threshold``:

.. code:: yaml

    creation_rules:
        - path_regex: .*keygroups.*
          shamir_threshold: 2
          key_groups:
              # First key group
              - pgp:
                    - fingerprint1
                    - fingerprint2
                kms:
                    - arn: arn1
                      role: role1
                      context:
                          foo: bar
                    - arn: arn2
                      aws_profile: myprofile
              # Second key group
              - pgp:
                    - fingerprint3
                    - fingerprint4
                kms:
                    - arn: arn3
                    - arn: arn4
              # Third key group
              - pgp:
                    - fingerprint5

And then run ``sops edit example.json``.

The threshold (``shamir_threshold``) is set to 2, so this configuration will require
master keys from two of the three different key groups in order to decrypt the file.
You can then decrypt the file the same way as with any other SOPS file:

.. code:: sh

    $ sops decrypt example.json

Key service
~~~~~~~~~~~

There are situations where you might want to run SOPS on a machine that
doesn't have direct access to encryption keys such as PGP keys. The ``sops`` key
service allows you to forward a socket so that SOPS can access encryption
keys stored on a remote machine. This is similar to GPG Agent, but more
portable.

SOPS uses a client-server approach to encrypting and decrypting the data
key. By default, SOPS runs a local key service in-process. SOPS uses a key
service client to send an encrypt or decrypt request to a key service, which
then performs the operation. The requests are sent using gRPC and Protocol
Buffers. The requests contain an identifier for the key they should perform
the operation with, and the plaintext or encrypted data key. The requests do
not contain any cryptographic keys, public or private.

**WARNING: the key service connection currently does not use any sort of
authentication or encryption. Therefore, it is recommended that you make sure
the connection is authenticated and encrypted in some other way, for example
through an SSH tunnel.**

Whenever we try to encrypt or decrypt a data key, SOPS will try to do so first
with the local key service (unless it's disabled), and if that fails, it will
try all other remote key services until one succeeds.

You can start a key service server by running ``sops keyservice``.

You can specify the key services the ``sops`` binary uses with ``--keyservice``.
This flag can be specified more than once, so you can use multiple key
services. The local key service can be disabled with
``enable-local-keyservice=false``.

For example, to decrypt a file using both the local key service and the key
service exposed on the unix socket located in ``/tmp/sops.sock``, you can run:

.. code:: sh

    $ sops decrypt --keyservice unix:///tmp/sops.sock file.yaml`

And if you only want to use the key service exposed on the unix socket located
in ``/tmp/sops.sock`` and not the local key service, you can run:

.. code:: sh

    $ sops decrypt --enable-local-keyservice=false --keyservice unix:///tmp/sops.sock file.yaml


