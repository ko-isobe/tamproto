# tamproto
- This is an [IETF TEEP](https://github.com/ietf-teep) prototype implementation.
- tamproto provides TAM server functions. Not covering device side (e.g TEEP Broker, TEEP Agent)

## Launch
### without Docker
+ At first, install necessary npm packages, run ``npm install``.
+ To run tamproto, type ``node app.js `` and execute.
+ To stop the tamproto, press Ctrl+C.
### with Docker (Recommended)
+ Build docker image by ``docker build -t tamproto .``
+ To run the container, run ``docker run -p 8443:8443 -p 8888:8888 tamproto``
+ To stop the tamproto, escape from the container by pressing Ctrl+C, and then type ``docker stop`` for stopping the container.

## API Endpoint
- tamproto has the API endpoints in   
``http://<Machine HostIP>:8888/api/tam`` (JSON)  
``http://<Machine HostIP>:8888/api/tam_cbor`` (CBOR)  
``http://<Machine HostIP>:8888/api/tam_cose`` (COSE)  
- These endpoints accept by HTTP POST method.
- tamproto exposes port 8888 (HTTP) and 8433 (HTTPS)
- Keys and certificates for TLS are stored in ``key`` directory.
- I'll add sample script/data for calling APIs soon.

## Implementation Structure
- tamproto uses [Express](https://expressjs.com/) framework.
- The above API is implemented in ``routes/apis.js``.

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