# fluent-plugin-encrypt

This is a [Fluentd](http://www.fluentd.org) filter plugin to encrypt data of specified fields using AES. This works in same way with [embulk-filter-encrypt](https://github.com/embulk/embulk-filter-encrypt).

Encrypted data is encoded using base64. For example, if you have following input records:

    {"id":1, "password":"super", "comment":"a"}
    {"id":2, "password":"secret", "comment":"b"}

You can apply encryption to password column and get following outputs:

    {"id":1, "password":"ayxU9lMA1iASdHGy/eAlWw==", "comment":"a"}
    {"id":2, "password":"v8ffsUOfspaqZ1KI7tPz+A==", "comment":"b"}

## Installation

Install with `gem` or `fluent-gem` (or `td-agent-gem`) command:

```
$ gem install fluent-plugin-encrypt
 
$ fluent-gem install fluent-plugin-encrypt
```

## Configuration

Key and IV hex string generation is required for AES (CBC) encryption before configuring Fluentd. This plugin gem includes the script to do it.

### Key and IV generation

Once you installed this plugin by `gem`, the script will be executable from your shell directly. Define password for encryption at first, then execute it.

```
$ fluent-plugin-encrypt-genkey AES-256-CBC "my secret passphrase"
key=668F3B7EA156BC3C4332CDD7C5AFDD604155F152C9055B0EACDFBB7708B687BA
iv =25443F5277938A2FD21725F273345C69
```

Copy these hex strings for Fluentd configuration.

### Filter plugin configuration

An example configuration to encrypt a field (named as "device_id"):

```apache
<source>
  @type  forward
  @label @myservice
  port   24224
</source>
 
<label @myservice>
  <filter **>
    @type encrypt
    algorithm       aes_256_cbc # default
    encrypt_key_hex 668F3B7EA156BC3C4332CDD7C5AFDD604155F152C9055B0EACDFBB7708B687BA
    encrypt_iv_hex  25443F5277938A2FD21725F273345C69
    key             device_id
    # Or, to encrypt values in some fields
    # keys ["device_id","user_id","session"]
  </filter>
  <match **>
    @type stdout
  </match>
</label>
```

Available algorithms (`algorithm` in configuration) are:

* **aes\_256\_cbc** (recommended)
* aes\_192\_cbc
* aes\_128\_cbc
* aes\_256\_ecb
* aes\_192\_ecb
* aes\_128\_ecb

For `fluent-plugin-encrypt-genkey`, use names with upcased chars and `-` instead of `_` (e.g. `AES-256-CBC`).

Other configuration parameters are:

* `encrypt_key_hex`: hex string for encryption key generated by scripts (NOT PASSWORD) [required]
* `encrypt_iv_hex`: hex string for encryption iv generated by scripts (omit for some encryption mode like ECB)
* `key`: key name of fields in records to be encrypted
* `keys`: JSON format list of key names to be encrypted

## Copyright

* Copyright (c) 2016- TAGOMORI Satoshi (tagomoris)
* License
  * Apache License, Version 2.0