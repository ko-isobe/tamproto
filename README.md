# tamproto
- This is an [IETF TEEP](https://github.com/ietf-teep) prototype implementation.
- tamproto provides TAM server functions. Not covering device side (e.g TEEP Broker, TEEP Agent)

## Launch
**See also [tamproto Quick Start](./quickstart.md)**
### with Docker (Recommended)
+ Build docker image by ``docker-compose up``
+ To stop the tamproto, escape from the container by pressing Ctrl+C, and then type ``docker stop`` for stopping the container.
### without Docker
+ At first, install necessary npm packages, run ``npm install``.
+ To run tamproto, type ``node app.js `` and execute.
+ To stop the tamproto, press Ctrl+C.

## API Endpoint
- tamproto has the API endpoints in   
``http://<Machine HostIP>:8888/api/tam_cbor`` (CBOR)  
``http://<Machine HostIP>:8888/api/tam_cose`` (COSE Signing)  
- These endpoints accept by HTTP POST method.
- tamproto exposes port 8888 (HTTP) and 8433 (HTTPS)
- Keys and certificates for TLS are stored in ``key`` directory.
- I'll add sample script/data for calling APIs soon.

## Configuration GUI
- To set up some parameters, tamproto has UIs accessible from webbrowser.
- ``http://<Machine HostIP>:8888/panel/`` (file/SUIT manifest static hosting)
- ``http://<Machine HostIP>:8888/panel/keys`` (keymanager)
- ``http://<Machine HostIP>:8888/panel/token`` (tokenmanager)

## Implementation Structure
- tamproto uses [Express](https://expressjs.com/) framework.
- The following code has each functions. Refer to each files for modifing or debugging tamproto.  
-- `app.js` bootstrap  
-- `apis.js` routing each API's request pass to TEEP-Protocol handler(`teep-p.js`)  
-- `teep-p.js` implement of TEEP protocol  
-- `keymanager.js` utility class of handling TEEP keys  
-- `tokenmanager.js` utility class of managing  TEEP protocol's token  
-- `panels.js` human interfaces of configuring tamproto

## Limitations
TEEP specification has some varietions in each functions. But tamproto doesn't all functions defined TEEP drafts.
- ciphersuite - just only supports ECDSA signature. Other signature algorithms and ciphermechanisms aren't implemented.
- freshness - just only supports token. Nor epoch and timestamp isn't implemented.
- attestation - tamproto can't pass EAT evidence to Verifier. AR can't be verified in tamproto. Just payload showed. (To be supported)
- suit report - suit report is also not implemented to parse as attestation is so.


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