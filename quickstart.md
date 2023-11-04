# tamproto Quick Start
This document describes the around of TEEP and how to try the tamproto briefly.

# About TEEP
TEEP (Trusted Execution Environments Provisioning) is the specification for distributing and managing TEE's Apps or data.
TEE is the security mechanisms for protecting sensitive "processing" from the attacks by isolation the exectuion environment.
TEE-enabled device usually has the two environment: TEE and REE.
REE (Rich Execution Environment) is usually execution space. OS and user's applications are runnning in there.
TEE is isolated from REE. So REE processess can't access or violate TEE's data or processing.
REE can invoke the TEE's application by specific commands or procedures.

TEEP gives the TEE-availabled device operators to the secure method of distributing or managing TEE's app or data.

# Walkthrough of TEEP
TEEP has mainly three entities: TAM, TEEP Broker, TEEP Agent.

TAM (Trusted Application Manager) has the role of distributing and managing Trusted Applications. TEE-enabled device asks the TAM for aquiring TAs.
TEEP Agent is running in the TEE to communicate with TAM. TEEP Agent can make request and result messages and receive the response from TAM.
TEEP Broker is running in the REE to pass the messages between TAM and TEEP Agent. 

Messages exchanged between TAM and TEEP Agents are defined as TEEP Protocol.
TEEP Protocol has 5 message types: QueryRequest, QueryResponse, Update, Success, Error.

Basic flow is the following steps:
1. TEEP-enabled device kicks the process. TEEP Broker calls TEEP Agent to start the process.
2. TEEP Agent responed accessing the TAM by HTTP to TEEP Broker.
3. TEEP Broker accessess the TAM by HTTP Post and get the QueryRequest response. QueryRequest contains the necessary information for TAM to decide what TA is delivered for the requested TEE-enabled device.
4. TEEP Broker pass the QueryRequest to TEEP Agent. TEEP Agent parses it and make QueryResponse message. 
5. TEEP Broker send the QueryResponse to TAM in new HTTP Post request.
6. TAM received the QueryResponse, parse the message and judge the delivering TAs. TAM makes Update message and embeds the SUIT manifests related to deliverying TAs.
7. TAM responed the Update messages on the HTTP Post response. TEEP Broker received Update message and pass to the TEEP Agent.
8. TEEP Agent conducted the TA install procedure along with Update messages and embeded SUIT manifests.
9. Finally, TEEP Agent reported the result of instaling by Success or Error messages to the TAM. TEEP Broker send the result message to the TAM by the new HTTP Post request.
10. TAM received the Result message. (And no body reponse.)

TEEP message's payload is encoded in CBOR and the whole message are protected by COSE.
Even though the TEEP broker in REE are compromised, TAM and TEEP Agent can detect or stop the malicious interrupt by verifing COSE messages.

# How to try TEEP?
tamproto is an implementation of TAM. This implementation can make and verify the TEEP messages, deliver the SUIT manifests.
If you have a TEEP-enabled device, you can use tamproto as an TA distributing server.

## Prepare

### Pulling
Recomended for runnning tamproto is using Docker.
At first, enabling docker and git in your machine.
```
$ sudo apt install git docker-ce docker-ce-cli containerd.io
```
Cloning tamproto's code from github.
```
$ git clone https://github.com/ko-isobe/tamproto.git
```

### Launch 
Type `docker-compose up` in the tamproto directory. tamproto outputs some logs. When you see these following messages, booting is finished.
```
[2022-07-20T13:05:12.285] [INFO] app.js - Express HTTP  server listening on port 8888 at <anonymous> (/usr/src/app/app.js:91:16)
[2022-07-20T13:05:12.286] [INFO] app.js - Express HTTPS server listening on port 8443 at <anonymous> (/usr/src/app/app.js:95:16)
```

### Rules
`rules.yml` is a configuration file for TAM to decide what TAs are delivered by TAM.
See the `teep-device` section. `rules` has some sets of TA's identifier.
Fill the two fields; `installed` is the field of indicating device-installed TA's identifiers. `updated` is the SUIT manifest filename embeded in Update when `installed` is matched with QueryResponse.
Note: To reflect the modifing of `rules.yml`, you need to reboot the tamproto.

### Key
tamproto has a human interface of key configuration.
Access `http://<tamproto>:8888/panel/keys`
You can add the TEE public key and get the TAM public key.
When you uploaded your key, you need set the your key as TEE public key.
(Currently tamproto only supports ECDSA P-256 key.)

### TA
tamproto has a simple static file hosting. You can store the SUIT manifests and TA binariers. Rules tries to find the specified SUIT manifest file from this hosting space.
To upload and confirm files, access `http://<tamproto>:8888/panel/`

## Try
tamproto has two API endpoints for TEEP-enabled device.
1. Plain cbor API. (No signing) `http://<tamproto>:8888/api/tam_cbor`
2. COSE Sign API. `http://<tamproto>:8888/api/tam_cose`

Please set the URI in your TEEP device and enjoy.

## Custom and Debug
tamproto outputs many logs and each logs contain the line number.
You can find the code to inspect tamproto's behaviour and fix as required.

## Other useful functions
### Token Manager
Token Manager provides the token table view. You can confirm the tokens and token status from webbrowser.
Access `http://<tamproto>:8888/panel/token`

# Oh, no. I don't have a TEEP-enabled device
OK, there are a device-side message processing library; libteep.
Open `docker-compose.yml`. `libteep` section is disabled.
De-comment out this section and run by `docker-compose up`.
libteep automatically access the tamproto and testing sending and receiving TEEP messages.
To see libteep's logs, input `docker logs -f <libteep's container id>`
```
PS D:\tamproto> cd d:\tamproto
PS D:\tamproto> docker-compose exec libteep
 <libteep's log>
```