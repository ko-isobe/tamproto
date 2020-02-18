tamproto
===
## What I have done
- compliant for JSON based TEEP Protocol
- JOSE(encrypt and sign JSON message)
- JWT based Keystore
- TA upload and delivery

## TBD and limitations
- compliant for CBOR based TEEP Protocol
- compliant OTrP(?)
- compliant SUIT
- Providing a TA is not variable. Just delivering static TA only (for AIST devices).
- TAM pushed TA delete

## How to Try
- tamproto supports HTTP and HTTPS  
`http://<tamproto ip>:8888/` and `https://<tamproto ip>:8443/`
- You can obtain a self-signed certificate by key management UI(see following Web Browser section)
### From TEEP Client
- tamproto provides two endpoints  
with plain JSON (no encryption)
`://<tamproto ip>:8888/api/tam`  
with JOSE (encrypted and signed)
`://<tamproto ip>:8888/api/tam_jose`
- You don't have TEEP client? You can try any REST client(e.g. Postman)
### From Web Browser
- You can manage TA and keys from Web Browser
- TA  
`://<tamproto ip>:8888/panel/`
- Key
`://<tamproto ip>:8888/panel/keys`
- Currently, you cannot change TA and keys even though you can upload those. Just obtain only.

## Issue?
### TA Delete
- We(AIST and I) think current TEEP drafts doesn't provide the method of device-driven TA delete.
- In other words, a device cannot request TA deleting for TAM server unless TA is not needed.
- For an experiment, issuing TA delete Message APIs are implemented.  
`://<tamproto ip>:8888/api/tam_delete` and `://<tamproto ip>:8888/api/tam_jose_delete`
- What's a trigger for TA delete? 