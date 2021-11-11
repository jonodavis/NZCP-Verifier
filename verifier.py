import base64
import hashlib
import json
import logging
from datetime import datetime
import requests
from cbor2 import dumps, loads
from jwcrypto import jwk
from ecdsa import VerifyingKey, BadSignatureError


logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')

TEST_CODES = {
    "VALID_CODE" : "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX",

    "BAD_PUBLIC_KEY" : "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAY73U6TCQ3KF5KFML5LRCS5D3PCYIB2D3EOIIZRPXPUA2OR3NIYCBMGYRZUMBNBDMIA5BUOZKVOMSVFS246AMU7ADZXWBYP7N4QSKNQ4TETIF4VIRGLHOXWYMR4HGQ7KYHHU",

    "PUBLIC_KEY_NOT_FOUND" : "NZCP:/1/2KCEVIQEIVVWK6JNGIASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVBMP3LEDMB4CLBS2I7IOYJZW46U2YIBCSOFZMQADVQGM3JKJBLCY7ATASDTUYWIP4RX3SH3IFBJ3QWPQ7FJE6RNT5MU3JHCCGKJISOLIMY3OWH5H5JFUEZKBF27OMB37H5AHF",

    "MODIFIED_SIGNATURE" : "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIAAAAAAAAAAAAAAAAC63WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX",

    "MODIFIED_PAYLOAD" : "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEOKKALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWKU3UMV3GK2TGMFWWS3DZJZQW2ZLDIRXWKY3EN5RGUMJZGYYC2MBUFUYTMB2QMCSPKTKOGBBTFPRTVV4LD2X2JNMEAAAAAAAAAAAAAAAABPN3J4NASOBXVEC5P3FC52BWW2ZK3IR4EMKU7OUIUUU7M5OWNBXOMMVQT3CYDKYI64VULCIEXMZZNUIPUZWRCR3Q",

    "EXPIRED_PASS" : "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUX5AM2FQIGTBPBPYWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA56TNJCCUN2NVK5NGAYOZ6VIWACYIBM3QXW7SLCMD2WTJ3GSEI5JH7RXAEURGATOHAHXC2O6BEJKBSVI25ICTBR5SFYUDSVLB2F6SJ63LWJ6Z3FWNHOXF6A2QLJNUFRQNTRU",

    "NOT_ACTIVE_PASS" : "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRU2XI5UFQIGTMZIQIWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA27NR3GFF4CCGWF66QGMJSJIF3KYID3KTKCBUOIKIC6VZ3SEGTGM3N2JTWKGDBAPLSG76Q3MXIDJRMNLETOKAUTSBOPVQEQAX25MF77RV6QVTTSCV2ZY2VMN7FATRGO3JATR"
}

TRUSTED_ISSUERS = [
    "did:web:nzcp.identity.health.nz",
    "did:web:nzcp.covid19.health.nz" # for testing only
]

stored_dids = {}


def addBase32Padding(base32InputNoPadding):
    """Return a base32 string with the correct padding

    Parameters:
    base32InputNoPadding (str): base32 string without padding
    """
    result = base32InputNoPadding 
    while ((len(result) % 8) != 0):
        result += '=' 
    return result


def check_and_remove_prefix(code):
    """Returns the NZCP code without the NZCP prefix

    Parameters:
    code (str): NZCP code with prefix
    """
    if (code[0:6] == "NZCP:/"):
        logging.debug("Check prefix: PASS")
        return code[6:]
    else:
        logging.debug("Check prefix: FAIL")
        return False 


def check_and_remove_version(base32_with_version):
    """Returns the NZCP code without the NZCP version

    Parameters:
    base32_with_version (str): NZCP code with version and without prefix
    """
    if (base32_with_version[0] == "1"):
        logging.debug("Checking version number: PASS")
        return base32_with_version[2:]
    else:
        logging.debug("Checking version number: FAIL")
        return False 


def decode_base32(base32_input):
    """Returns the decoded base32 string

    Parameters:
    base32_input (str): base32 string
    """
    try:
        result = base64.b32decode(base32_input)
        logging.debug("Decoding Base32: PASS")
        return result
    except:
        logging.debug("Decoding Base32: FAIL")
        return False


def decode_cbor(decoded_base32):
    """Returns the deserialized CBOR object

    Parameters:
    decoded_base32 (bytes): decoded base32 string
    """
    try:
        obj = loads(decoded_base32)
        logging.debug("Decoding CBOR: PASS")
        return obj
    except:
        logging.debug("Decoing CBOR: FAIL")
        return False


def check_cwt_claims(decoded_payload):
    """Returns True if the CWT claims are valid

    Parameters:
    decoded_payload (dict): decoded CBOR object
    """
    for i in [1, 4, 5, 7, 'vc']:
        if i not in decoded_payload:
            logging.debug("Checking CWT headers: FAIL")
            return False
    
    if decoded_payload[1] not in TRUSTED_ISSUERS:
        logging.debug("Checking CWT headers: FAIL")
        return False
    
    logging.debug("Checking CWT headers: PASS")

    if datetime.now() < datetime.utcfromtimestamp(decoded_payload[5]):
        logging.debug("Checking not before date: FAIL")
        return False
    logging.debug("Checking not before date: PASS")

    if datetime.now() > datetime.utcfromtimestamp(decoded_payload[4]):
        logging.debug("Checking expiry date: FAIL")
        return False
    logging.debug("Checking expiry date: PASS")

    return True

def decode_UUID(encoded_UUID):
    """Returns the decoded UUID

    Parameters:
    encoded_UUID (str): encoded UUID
    """
    try:
        result = encoded_UUID.hex()
        result = result[0:8] + "-" + result[8:12] + "-" + result[12:16] + "-" + result[16:20] + "-" + result[20:32]
        result = "urn:uuid:" + result
        logging.debug("Decoding UUID: PASS")
        return result
    except:
        logging.debug("Decoding UUID: FAIL")
        return False


def get_DID_from_issuer(iss):
    """Returns the DID fetched from the issuer

    Parameters:
    iss (str): issuer
    """
    try:
        url = iss.replace("did:web:", "https://")
        url += "/.well-known/did.json"
        did_json = requests.get(url).json()
        stored_dids[iss] = did_json
        logging.debug("Getting DID from issuer: PASS")
        return did_json 
    except:
        logging.debug("Getting DID from issuer: FAIL")
        return False


def validate_DID(iss, protected_headers, did):
    """Returns True if the DID is valid

    Parameters:
    iss (str): issuer
    protected_headers (dict): decoded protected headers
    did (dict): DID retrieved from the issuer
    """
    absolute_key_reference = iss + "#" + protected_headers[4].decode()
    if absolute_key_reference not in did["assertionMethod"]:
        logging.debug("Validating DID: FAIL")
        return False
    if did["verificationMethod"][0]["type"] != "JsonWebKey2020":
        logging.debug("Validating DID: FAIL")
        return False
    logging.debug("Validating DID: PASS")
    return True


def get_issuer_public_key_from_did(did):
    """Returns the public key from the DID

    Parameters:
    did (dict): DID retrieved from the issuer
    """
    try:
        issuer_publc_key = did["verificationMethod"][0]["publicKeyJwk"]
        logging.debug("Extracting public key from issuer DID: PASS")
        return issuer_publc_key
    except:
        logging.debug("Extracting public key from issuer DID: FAIL")
        return False


def convert_jwk_to_pem(jwt_public_key):
    """Returns the public key in PEM format

    Parameters:
    jwt_public_key (dict): public key in JWK format
    """
    json_jwt = json.dumps(jwt_public_key) 
    key = jwk.JWK.from_json(json_jwt)
    pem_key = key.export_to_pem()
    return pem_key


def generate_sig_structure(protected_headers, payload):
    """Returns the encoded signature structure

    Parameters:
    protected_headers (dict): decoded protected headers
    payload (dict): decoded payload
    """
    try:
        sig_structure = ["Signature1"] 
        sig_structure.append(protected_headers)
        sig_structure.append(b'')
        sig_structure.append(payload)
        logging.debug("Generating Sig_structure: PASS")
        return dumps(sig_structure)
    except:
        logging.debug("Generating Sig_structure: FAIL")
        return False


def validate_signature(signature, pem_key, message):
    """Returns True if the signature is valid

    Parameters:
    signature (bytes): digital signature
    pem_key (bytes): public key in PEM format
    message (bytes): signature structure to be verified
    """
    public_key = VerifyingKey.from_pem(pem_key, hashfunc=hashlib.sha256)
    try:
        result = public_key.verify(signature, message, hashfunc=hashlib.sha256)
        logging.debug("Validating digital signature: PASS")
        return result
    except BadSignatureError:
        logging.debug("Validating digital signature: FAIL")
        return False


def construct_response(validated, decoded_CWT_payload=None, uuid=None):
    """Returns the correctly formatted response to be sent to the client

    Parameters:
    validated (bool): True if the NZCP is valid
    decoded_CWT_payload (dict): decoded CWT payload (default None)
    uuid (str): UUID (default None)
    """
    # EXAMPLE VALIDATED RESPONSE
    # {
    #   "verified": true,
    #   "payload": {
    #       "givenName": "Samantha",
    #       "familyName": "Gill",
    #       "dob": "1984-08-07"
    #   },
    #   "metadata": {
    #     "expiry": "2022-02-20T12:34:56.000Z",
    #     "notBefore": "2020-01-20T12:34:56.000Z",
    #     "id": "urn:uuid:850a1de1-f890-4be5-b105-d721e5f3bc98",
    #     "issuer": "did:web:example.com",
    #     "type": "PublicCovidPass"
    #   }
    # }
    res = {}
    if validated:
        res["verified"] = validated
        res["payload"] = decoded_CWT_payload["vc"]["credentialSubject"]
        res["metadata"] = {}
        res["metadata"]["expiry"] = datetime.utcfromtimestamp(decoded_CWT_payload[4]).isoformat()
        res["metadata"]["notBefore"] = datetime.utcfromtimestamp(decoded_CWT_payload[5]).isoformat()
        res["metadata"]["id"] = uuid
        res["metadata"]["issuer"] = decoded_CWT_payload[1]
        res["metadata"]["type"] = decoded_CWT_payload["vc"]["type"][1]
        return res
    else:
        res["verified"] = validated
        return res



def check_code(code_to_check):
    """Checks whether NZCP is valid and returns the response to be sent to the client

    Parameters:
    code_to_check (str): NZCP to be checked
    """
    try:
        base32_input_without_prefix = check_and_remove_prefix(code_to_check)
        if not base32_input_without_prefix:
            return construct_response(False) 

        base32_input = check_and_remove_version(base32_input_without_prefix)
        if not base32_input:
            return construct_response(False) 

        padded = addBase32Padding(base32_input)

        decoded = decode_base32(padded)
        if not decoded:
            return construct_response(False) 

        decoded_COSE_structure = decode_cbor(decoded).value
        if not decoded_COSE_structure:
            return construct_response(False) 

        decoded_CWT_protected_headers = decode_cbor(decoded_COSE_structure[0])
        if not decoded_CWT_protected_headers:
            return construct_response(False) 

        decoded_CWT_payload = decode_cbor(decoded_COSE_structure[2])
        if not decoded_CWT_payload:
            return construct_response(False) 

        if not check_cwt_claims(decoded_CWT_payload):
            return construct_response(False) 

        decoded_UUID = decode_UUID(decoded_CWT_payload[7])
        if not decoded_UUID:
            return construct_response(False)

        if decoded_CWT_payload[1] in stored_dids:
            did_json = stored_dids[decoded_CWT_payload[1]]
        else:
            did_json = get_DID_from_issuer(decoded_CWT_payload[1])
            if not did_json:
                return construct_response(False) 

        if not validate_DID(decoded_CWT_payload[1], decoded_CWT_protected_headers, did_json):
            return construct_response(False) 

        signature = decoded_COSE_structure[3]

        issuer_public_key = get_issuer_public_key_from_did(did_json)
        if not issuer_public_key:
            return construct_response(False) 

        pem_key = convert_jwk_to_pem(issuer_public_key)

        to_be_signed = generate_sig_structure(decoded_COSE_structure[0], decoded_COSE_structure[2])
        if not to_be_signed:
            return False

        validated = validate_signature(signature, pem_key, to_be_signed)
        if not validated:
            return construct_response(False) 

        return construct_response(validated, decoded_CWT_payload, decoded_UUID)

    except:
        return construct_response(False)


def main():
    for k, v in TEST_CODES.items():
        print(k + ":", check_code(v))
        logging.debug("----------------------------------------------------")
        

if __name__=="__main__":
    main()