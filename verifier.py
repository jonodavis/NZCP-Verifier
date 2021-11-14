import base64
import hashlib
import json
import logging
from datetime import datetime
import requests
from cbor2 import dumps, loads
from jwcrypto import jwk
from ecdsa import VerifyingKey 


logging.basicConfig(level=logging.WARN,
                    format='%(asctime)s - %(levelname)s - %(message)s')

TRUSTED_ISSUERS = [
    "did:web:nzcp.identity.health.nz",
    "did:web:nzcp.covid19.health.nz"  # for testing only
]

stored_dids = {}


def add_base32_padding(base32_input_no_padding):
    """Return a base32 string with the correct padding

    Parameters:
    base32_input_no_padding (str): base32 string without padding
    """
    result = base32_input_no_padding
    while ((len(result) % 8) != 0):
        result += '='
    return result


def check_and_remove_prefix(code):
    """Returns the NZCP code without the NZCP prefix

    Parameters:
    code (str): NZCP code with prefix
    """
    try:
        if (code[0:6] == "NZCP:/"):
            logging.debug("Check prefix: PASS")
            return code[6:]
        else:
            logging.debug("Check prefix: FAIL")
            return False
    except:
        logging.debug("Check prefix: FAIL")
        return False


def check_and_remove_version(base32_with_version):
    """Returns the NZCP code without the NZCP version

    Parameters:
    base32_with_version (str): NZCP code with version and without prefix
    """
    try:
        if (base32_with_version[0:2] == "1/"):
            logging.debug("Checking version number: PASS")
            return base32_with_version[2:]
        else:
            logging.debug("Checking version number: FAIL")
            return False
    except:
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
    try:
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
    except:
        logging.debug("Checking CWT headers: FAIL")
        return False


def decode_UUID(encoded_UUID):
    """Returns the decoded UUID

    Parameters:
    encoded_UUID (bytes): encoded UUID
    """
    try:
        if len(encoded_UUID) != 16:
            logging.debug("Checking UUID length: FAIL")
            return False
        result = encoded_UUID.hex()
        result = result[0:8] + "-" + result[8:12] + "-" + \
            result[12:16] + "-" + result[16:20] + "-" + result[20:32]
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
    try:
        absolute_key_reference = iss + "#" + protected_headers[4].decode()
        if absolute_key_reference not in did["assertionMethod"]:
            logging.debug("Validating DID: FAIL")
            return False
        if did["verificationMethod"][0]["type"] != "JsonWebKey2020":
            logging.debug("Validating DID: FAIL")
            return False
        logging.debug("Validating DID: PASS")
        return True
    except:
        logging.debug("Validating DID: FAIL")
        return False


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
    try:
        json_jwt = json.dumps(jwt_public_key)
        key = jwk.JWK.from_json(json_jwt)
        pem_key = key.export_to_pem()
        logging.debug("Converting JWK to PEM: PASS")
        return pem_key
    except:
        logging.debug("Converting JWK to PEM: FAIL")
        return False


def generate_sig_structure(protected_headers, payload):
    """Returns the encoded signature structure

    Parameters:
    protected_headers (dict): decoded protected headers
    payload (dict): decoded payload
    """
    try:
        sig_structure = ["Signature1"]
        sig_structure.append(protected_headers)
        sig_structure.append(b'') # type: ignore
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
    try:
        public_key = VerifyingKey.from_pem(pem_key, hashfunc=hashlib.sha256)
        result = public_key.verify(signature, message, hashfunc=hashlib.sha256)
        logging.debug("Validating digital signature: PASS")
        return result
    except:
        logging.debug("Validating digital signature: FAIL")
        return False


def construct_response(validated, decoded_COSE_payload=None, uuid=None):
    """Returns the correctly formatted response to be sent to the client

    Parameters:
    validated (bool): True if the NZCP is valid
    decoded_COSE_payload (dict): decoded COSE payload (default None)
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
    try:
        if validated:
            res["verified"] = validated
            res["payload"] = decoded_COSE_payload["vc"]["credentialSubject"]
            res["metadata"] = {}
            res["metadata"]["expiry"] = datetime.utcfromtimestamp(
                decoded_COSE_payload[4]).isoformat()
            res["metadata"]["notBefore"] = datetime.utcfromtimestamp(
                decoded_COSE_payload[5]).isoformat()
            res["metadata"]["id"] = uuid
            res["metadata"]["issuer"] = decoded_COSE_payload[1]
            res["metadata"]["type"] = decoded_COSE_payload["vc"]["type"][1]
            logging.debug("Constructing response: PASS")
            return res
        else:
            res["verified"] = validated
            logging.debug("Constructing response: PASS")
            return res
    except:
        logging.debug("Constructing response: FAIL")
        res["verified"] = False
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

        padded = add_base32_padding(base32_input)

        decoded = decode_base32(padded)
        if not decoded:
            return construct_response(False)

        decoded_COSE_structure = decode_cbor(decoded).value # type: ignore
        if not decoded_COSE_structure:
            return construct_response(False)

        decoded_COSE_protected_headers = decode_cbor(decoded_COSE_structure[0])
        if not decoded_COSE_protected_headers:
            return construct_response(False)

        decoded_COSE_payload = decode_cbor(decoded_COSE_structure[2])
        if not decoded_COSE_payload:
            return construct_response(False)

        if not check_cwt_claims(decoded_COSE_payload):
            return construct_response(False)

        decoded_UUID = decode_UUID(decoded_COSE_payload[7])
        if not decoded_UUID:
            return construct_response(False)

        if decoded_COSE_payload[1] in stored_dids:
            did_json = stored_dids[decoded_COSE_payload[1]]
        else:
            did_json = get_DID_from_issuer(decoded_COSE_payload[1])
            if not did_json:
                return construct_response(False)

        if not validate_DID(decoded_COSE_payload[1], decoded_COSE_protected_headers, did_json):
            return construct_response(False)

        signature = decoded_COSE_structure[3]

        issuer_public_key = get_issuer_public_key_from_did(did_json)
        if not issuer_public_key:
            return construct_response(False)

        pem_key = convert_jwk_to_pem(issuer_public_key)

        to_be_signed = generate_sig_structure(
            decoded_COSE_structure[0], decoded_COSE_structure[2])
        if not to_be_signed:
            return False

        validated = validate_signature(signature, pem_key, to_be_signed)
        if not validated:
            return construct_response(False)

        return construct_response(validated, decoded_COSE_payload, decoded_UUID)

    except:
        return construct_response(False)


def main():
    logging.warning("Run application.py to start the server")


if __name__ == "__main__":
    main()
