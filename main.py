import base64
import hashlib
import json
from datetime import datetime
import requests
from cbor2 import dumps, loads
from jwcrypto import jwk
from ecdsa import VerifyingKey, BadSignatureError


VALID_CODE = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

BAD_PUBLIC_KEY = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAY73U6TCQ3KF5KFML5LRCS5D3PCYIB2D3EOIIZRPXPUA2OR3NIYCBMGYRZUMBNBDMIA5BUOZKVOMSVFS246AMU7ADZXWBYP7N4QSKNQ4TETIF4VIRGLHOXWYMR4HGQ7KYHHU"

PUBLIC_KEY_NOT_FOUND = "NZCP:/1/2KCEVIQEIVVWK6JNGIASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVBMP3LEDMB4CLBS2I7IOYJZW46U2YIBCSOFZMQADVQGM3JKJBLCY7ATASDTUYWIP4RX3SH3IFBJ3QWPQ7FJE6RNT5MU3JHCCGKJISOLIMY3OWH5H5JFUEZKBF27OMB37H5AHF"

MODIFIED_SIGNATURE = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIAAAAAAAAAAAAAAAAC63WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX"

MODIFIED_PAYLOAD = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEOKKALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWKU3UMV3GK2TGMFWWS3DZJZQW2ZLDIRXWKY3EN5RGUMJZGYYC2MBUFUYTMB2QMCSPKTKOGBBTFPRTVV4LD2X2JNMEAAAAAAAAAAAAAAAABPN3J4NASOBXVEC5P3FC52BWW2ZK3IR4EMKU7OUIUUU7M5OWNBXOMMVQT3CYDKYI64VULCIEXMZZNUIPUZWRCR3Q"

EXPIRED_PASS = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUX5AM2FQIGTBPBPYWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA56TNJCCUN2NVK5NGAYOZ6VIWACYIBM3QXW7SLCMD2WTJ3GSEI5JH7RXAEURGATOHAHXC2O6BEJKBSVI25ICTBR5SFYUDSVLB2F6SJ63LWJ6Z3FWNHOXF6A2QLJNUFRQNTRU"

NOT_ACTIVE_PASS = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRU2XI5UFQIGTMZIQIWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA27NR3GFF4CCGWF66QGMJSJIF3KYID3KTKCBUOIKIC6VZ3SEGTGM3N2JTWKGDBAPLSG76Q3MXIDJRMNLETOKAUTSBOPVQEQAX25MF77RV6QVTTSCV2ZY2VMN7FATRGO3JATR"

TRUSTED_ISSUERS = [
    "did:web:nzcp.identity.health.nz",
    "did:web:nzcp.covid19.health.nz" # for testing only
]


def addBase32Padding(base32InputNoPadding):
    result = base32InputNoPadding 
    while ((len(result) % 8) != 0):
        result += '=' 
    return result


def check_and_remove_prefix(padded_base32_input):
    if (padded_base32_input[0:6] == "NZCP:/"):
        print("Check prefix: PASS")
        return padded_base32_input[6:]
    else:
        print("Check prefix: FAIL")
        return False 


def check_and_remove_version(base32_with_version):
    if (base32_with_version[0] == "1"):
        print("Checking version number: PASS")
        return base32_with_version[2:]
    else:
        print("Checking version number: FAIL")
        return False 


def decode_base32(base32_input):
    try:
        result = base64.b32decode(base32_input)
        print("Decoding Base32: PASS")
        return result
    except:
        print("Decoding Base32: FAIL")
        return False


def decode_cbor(decoded_base32):
    try:
        obj = loads(decoded_base32)
        print("Decoding CBOR: PASS")
        return obj
    except:
        print("Decoing CBOR: FAIL")
        return False


def check_cwt_claims(decoded_payload):
    for i in [1, 4, 5, 7, 'vc']:
        if i not in decoded_payload:
            print("Checking CWT headers: FAIL")
            return False
    
    if decoded_payload[1] not in TRUSTED_ISSUERS:
        print("Checking CWT headers: FAIL")
        return False
    
    print("Checking CWT headers: PASS")

    if datetime.now() < datetime.utcfromtimestamp(decoded_payload[5]):
        print("Checking not before date: FAIL")
        return False
    print("Checking not before date: PASS")

    if datetime.now() > datetime.utcfromtimestamp(decoded_payload[4]):
        print("Checking expiry date: FAIL")
        return False
    print("Checking expiry date: PASS")

    return True


def get_DID_from_issuer(iss):
    try:
        iss = iss.replace("did:web:", "https://")
        iss += "/.well-known/did.json"
        did_json = requests.get(iss).json()
        print("Getting DID from issuer: PASS")
        return did_json 
    except:
        print("Getting DID from issuer: FAIL")
        return False


def validate_DID(iss, protected_headers, did):
    absolute_key_reference = iss + "#" + protected_headers[4].decode()
    if absolute_key_reference not in did["assertionMethod"]:
        print("Validating DID: FAIL")
        return False
    if did["verificationMethod"][0]["type"] != "JsonWebKey2020":
        print("Validating DID: FAIL")
        return False
    print("Validating DID: PASS")
    return True


def get_issuer_public_key_from_did(did_json):
    try:
        issuer_publc_key = did_json["verificationMethod"][0]["publicKeyJwk"]
        print("Extracting public key from issuer DID: PASS")
        return issuer_publc_key
    except:
        print("Extracting public key from issuer DID: FAIL")
        return False


def convert_jwk_to_pem(jwt_public_key):
    json_jwt = json.dumps(jwt_public_key) 
    key = jwk.JWK.from_json(json_jwt)
    pem_key = key.export_to_pem()
    return pem_key


def generate_sig_structure(protected_headers, payload):
    try:
        sig_structure = ["Signature1"] 
        sig_structure.append(protected_headers)
        sig_structure.append(b'')
        sig_structure.append(payload)
        print("Generating Sig_structure: PASS")
        return dumps(sig_structure)
    except:
        print("Generating Sig_structure: FAIL")
        return False


def validate_signature(signature, pem_key, message):
    public_key = VerifyingKey.from_pem(pem_key, hashfunc=hashlib.sha256)
    try:
        result = public_key.verify(signature, message, hashfunc=hashlib.sha256)
        print("Validating digital signature: PASS")
        return result
    except BadSignatureError:
        print("Validating digital signature: FAIL")
        return False
    

def check_code(code_to_check):
    padded = addBase32Padding(code_to_check)
    # print(padded)

    base32_input_without_prefix = check_and_remove_prefix(padded)
    if not base32_input_without_prefix:
        return False
    # print(base32_input_without_prefix)

    base32_input = check_and_remove_version(base32_input_without_prefix)
    if not base32_input:
        return False
    # print(base32_input)

    decoded = decode_base32(base32_input)
    if not decoded:
        return False
    # print(decoded.hex())

    decoded_COSE_structure = decode_cbor(decoded).value
    if not decoded_COSE_structure:
        return False
    # print(decoded_COSE_structure)

    decoded_CWT_protected_headers = decode_cbor(decoded_COSE_structure[0])
    if not decoded_CWT_protected_headers:
        return False
    # print(decoded_CWT_protected_headers)

    decoded_CWT_payload = decode_cbor(decoded_COSE_structure[2])
    if not decoded_CWT_payload:
        return False
    # print(decoded_CWT_payload)

    if not check_cwt_claims(decoded_CWT_payload):
        return False

    did_json = get_DID_from_issuer(decoded_CWT_payload[1])
    if not did_json:
        return False
    # print(did_json)

    if not validate_DID(decoded_CWT_payload[1], decoded_CWT_protected_headers, did_json):
        return False 

    signature = decoded_COSE_structure[3]
    # print(signature)

    issuer_public_key = get_issuer_public_key_from_did(did_json)
    if not issuer_public_key:
        return False
    # print(issuer_public_key)

    pem_key = convert_jwk_to_pem(issuer_public_key)
    # print(pem_key)

    to_be_signed = generate_sig_structure(decoded_COSE_structure[0], decoded_COSE_structure[2])
    if not to_be_signed:
        return False
    # print(to_be_signed)

    validated = validate_signature(signature, pem_key, to_be_signed)
    if not validated:
        return False

    return True 


def main():
    print(check_code(VALID_CODE))
    print("----------------------------------------")
    print(check_code(BAD_PUBLIC_KEY))
    print("----------------------------------------")
    print(check_code(PUBLIC_KEY_NOT_FOUND))
    print("----------------------------------------")
    print(check_code(MODIFIED_SIGNATURE))
    print("----------------------------------------")
    print(check_code(MODIFIED_PAYLOAD))
    print("----------------------------------------")
    print(check_code(EXPIRED_PASS))
    print("----------------------------------------")
    print(check_code(NOT_ACTIVE_PASS))


if __name__=="__main__":
    main()
