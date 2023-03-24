# tamproto
- This is an [IETF TEEP](https://github.com/ietf-teep) prototype implementation.
- tamproto provides TAM server functionality. The device side, e.g. the TEEP Broker and the TEEP Agent, is not supported. 
- The implemantation is along with mainly [TEEP Protocol specification](https://datatracker.ietf.org/doc/draft-ietf-teep-protocol/) and [ietf-teep-otrp-over-http](https://datatracker.ietf.org/doc/draft-ietf-teep-otrp-over-http/).

## Launch
**See also [tamproto Quick Start](./quickstart.md)**

### With Docker (Recommended)
+ Build docker image by ``docker-compose up``
+ To stop the tamproto, escape from the container by pressing Ctrl+C, and then type ``docker stop`` for stopping the container.

### Without Docker
+ At first, install necessary npm packages, run ``npm install``.
+ To run tamproto, type ``node app.js `` and execute.
+ To stop the tamproto, press Ctrl+C.

## API Endpoint
- tamproto has the API endpoints in   
``http://<Machine HostIP>:8888/api/tam_cbor`` (CBOR)  
``http://<Machine HostIP>:8888/api/tam_cose`` (COSE Signing)  
- These endpoints accept by HTTP POST method. (See [ietf-teep-otrp-over-http](https://datatracker.ietf.org/doc/draft-ietf-teep-otrp-over-http/))
- tamproto exposes port 8888 (HTTP) and 8443 (HTTPS)
- I'll add sample script/data for calling APIs soon. (Sample teep message binaries are available in TEEP protocol drafts and [kentakayama/libteep](https://github.com/kentakayama/libteep/tree/master/testfiles))

## Configuration
### TAM Signing Key
- TAM has a private key for signing TEEP message to TEEP Agents.
- Store an ECDSA P-256 private jwk file in `key` directory and write its filename into `key["TAM_priv"]` field in `config.json`. 
### TEEP Agent Public Key
- TAM verifies the Agent's messages by using TEEP Agent's public key.
- Store an ECDSA P-256 public jwk files in `key` directory and write its filename into `key["TEE_pub"]` field in `config.json`. 
- If you want to use several public keys for handling different Agents, you can store multiple keys in the same directory. See the following section.
### Provisioning Data and rules
- To specify the provisioning data (usually SUIT manifest binaries), write your rules in `rules.json`.
- First block is a device name field. This fields are used as just indicating device names in tamproto output.
- `key` field is to specify each Agent public key's filename. This keyfile is required to contain `kid` for distinguishing Agents. When using multiple Agents, each Agent should contain same `kid` in the COSE unprotected header.
- `rules` field holds pairs to Agent's request TC-lists and TAM's response manifest. The `requested` field is match to the `requested-tc-list` in QueryResponse. And the `update` field is match to the `manifest-list` in QueryResponse. (See [ietf-teep-protocol Section 4.2 and 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-12))
### Attestation
- tamproto supports Passport model. Background-check model isn't so.
- When QueryResponse contains Attestation Results EAT, tamproto tries to verify it by the following Verifier public key.
- Store an Verifier ECDSA P-256 public jwk file in `key` directory and write its filename into `key["Verify"]` field in `config.json`.
### TLS Keys
- When using TLS connection between TAM and TEEP brokers, you can obtain the TLS Keys and Certificates in the `key` directory.
- If you want to use your own keys and certs, replace these files with keeping the same filenames.

## Monitoring and Debugging
- tamproto outputs the log of TAM behaviour, arriving messages and sending messages in console.
- The token list is also available in ``http://<Machine HostIP>:8888/panel/token`` (tokenmanager).

## Implementation Structure
- tamproto uses the [Express](https://expressjs.com/) framework.
- The following code has each functions. Refer to each files for modifing or debugging tamproto.  
-- `app.js` bootstrap  
-- `apis.js` routing each API's request pass to TEEP-Protocol handler(`teep-p.js`). Signing and Verifying COSE signatures.  
-- `teep-p.js` implement of TEEP protocol  
-- `rats.js` implement of EAT Signature and claims verification
-- `keymanager.js` utility class of handling TEEP keys  
-- `tokenmanager.js` utility class of managing TEEP protocol's token 
-- `panels.js` human interfaces of configuring tamproto

## Limitations and Wish list
The TEEP specification offers optional features and tamproto supports a subset of these options.

The following features are implemented:
- Only ES256 signature is supported. Other EdDSA and Cipher-Algorithm choosing aren't supported yet.
- freshness is only supported for tokens. Neither epoch nor timestamp support is implemented.
- attestation: tamproto cannot pass EAT evidence to a verifier and cannot be verified by tamproto. Instead, the EAT payload is displayed showed.
- suit report is not supported.

## License
```
Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
