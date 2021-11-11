# NZ COVID Pass Verifier 
This is an API which verifies whether an NZ COVID Pass is valid or not. There is an instance of this API running on https://api.pancake.nz/verify which can be used free of charge to validate NZ COVID Passes. If you wish to run the API yourself, you can follow the steps below.

**NOTE:** The API does not store any data from NZ COVID Passes other than in short-term memory whilst checking the validity of the pass.

## Steps to run the API locally
1. Create a new virtual environment:
```
python3 -m venv ./venv
```
2. Activate virtual environment:
```
source ./venv/bin/activate
```
3. Install requirements:
```
pip install -r requirements.txt
```
4. Start API:
```
python application.py
```
Or using gunicorn for production environments:
```
gunicorn -w 4 -b 0.0.0.0:8080 application:application
```
The API will now be listening for POST requests at http://localhost:5000/verify on port 5000.

## Sending an NZCP to the API for verification
The API accepts HTTP POST requests only. The only required header is `Content-Type: application/json`. The body of the request should be a JSON object with the following fields:
```json
{
    "payload": "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"
}
```
The `payload` field is the NZCP to be verified.

### Successful Response
```json
{
    "metadata": {
        "expiry": "2031-11-02T20:05:30",
        "id": "urn:uuid:60a4f54d-4e30-4332-be33-ad78b1eafa4b",
        "issuer": "did:web:nzcp.covid19.health.nz",
        "notBefore": "2021-11-02T20:05:30",
        "type": "PublicCovidPass"
    },
    "payload": {
        "dob": "1960-04-16",
        "familyName": "Sparrow",
        "givenName": "Jack"
    },
    "verified": true
}
```

### Unsuccessful Response
```json
{
    "verified": false
}
```