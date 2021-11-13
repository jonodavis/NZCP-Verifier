import unittest
import verifier

class TestVerifierFunctions(unittest.TestCase):

    def setUp(self):
        self.valid_decoded_cose_struct = [
            b'\xa2\x04Ekey-1\x01&', 
            {}, 
            b'\xa5\x01x\x1edid:web:nzcp.covid19.health.nz\x05\x1aa\x81\x9a\n\x04\x1atP@\nbvc\xa4h@context\x82x&https://www.w3.org/2018/credentials/v1x*https://nzcp.covid19.health.nz/contexts/v1gversione1.0.0dtype\x82tVerifiableCredentialoPublicCovidPassqcredentialSubject\xa3igivenNamedJackjfamilyNamegSparrowcdobj1960-04-16\x07P`\xa4\xf5MN0C2\xbe3\xadx\xb1\xea\xfaK', 
            b'\xd2\xe0{\x1d\xd7&=\x831f\xbd\xbbO\x1a\t87\xa9\x05\xd7\xec\xa2\xee\x83kk*\xda#\xc21T\xfb\xa8\x8aR\x9fg]f\x86\xeec+\t\xecX\x1a\xb0\x8fr\xb4X\x90K\xb39m\x10\xfaf\xd1\x14w'
        ]
        self.valid_cbor_payload_in_hex = "a501781e6469643a7765623a6e7a63702e636f76696431392e6865616c74682e6e7a051a61819a0a041a7450400a627663a46840636f6e7465787482782668747470733a2f2f7777772e77332e6f72672f323031382f63726564656e7469616c732f7631782a68747470733a2f2f6e7a63702e636f76696431392e6865616c74682e6e7a2f636f6e74657874732f76316776657273696f6e65312e302e306474797065827456657269666961626c6543726564656e7469616c6f5075626c6963436f766964506173737163726564656e7469616c5375626a656374a369676976656e4e616d65644a61636b6a66616d696c794e616d656753706172726f7763646f626a313936302d30342d3136075060a4f54d4e304332be33ad78b1eafa4b"
        self.valid_cbor_payload = {
            1: 'did:web:nzcp.covid19.health.nz',
            5: 1635883530,
            4: 1951416330,
            'vc': {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://nzcp.covid19.health.nz/contexts/v1'
                ],
                'version': '1.0.0',
                'type': [
                    'VerifiableCredential',
                    'PublicCovidPass'
                ],
                'credentialSubject': {
                    'givenName': 'Jack',
                    'familyName': 'Sparrow',
                    'dob': '1960-04-16'
                }
            },
            7: b'`\xa4\xf5MN0C2\xbe3\xadx\xb1\xea\xfaK'
        }
        self.valid_did = {
            "@context": "https://w3.org/ns/did/v1",
            "id": "did:web:nzcp.covid19.health.nz",
            "verificationMethod": [
                {
                "id": "did:web:nzcp.covid19.health.nz#key-1",
                "controller": "did:web:nzcp.covid19.health.nz",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "zRR-XGsCp12Vvbgui4DD6O6cqmhfPuXMhi1OxPl8760",
                    "y": "Iv5SU6FuW-TRYh5_GOrJlcV_gpF_GpFQhCOD8LSk3T0"
                }
                }
            ],
            "assertionMethod": [
                "did:web:nzcp.covid19.health.nz#key-1"
            ]
        }
        self.valid_public_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "zRR-XGsCp12Vvbgui4DD6O6cqmhfPuXMhi1OxPl8760",
            "y": "Iv5SU6FuW-TRYh5_GOrJlcV_gpF_GpFQhCOD8LSk3T0"
        }
        self.valid_pem_key = b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzRR+XGsCp12Vvbgui4DD6O6cqmhf\nPuXMhi1OxPl8760i/lJToW5b5NFiHn8Y6smVxX+CkX8akVCEI4PwtKTdPQ==\n-----END PUBLIC KEY-----\n'
        self.valid_encoded_headers = "a204456b65792d310126"
        self.valid_cbor_protected_headers = {4: b'key-1', 1: -7}
        self.valid_uuid_hex = "f81d4fae7dec11d0a76500a0c91e6bf6"
        self.valid_uuid = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
        self.valid_sig_struct = "846a5369676e6174757265314aa204456b65792d3101264059011fa501781e6469643a7765623a6e7a63702e636f76696431392e6865616c74682e6e7a051a61819a0a041a7450400a627663a46840636f6e7465787482782668747470733a2f2f7777772e77332e6f72672f323031382f63726564656e7469616c732f7631782a68747470733a2f2f6e7a63702e636f76696431392e6865616c74682e6e7a2f636f6e74657874732f76316776657273696f6e65312e302e306474797065827456657269666961626c6543726564656e7469616c6f5075626c6963436f766964506173737163726564656e7469616c5375626a656374a369676976656e4e616d65644a61636b6a66616d696c794e616d656753706172726f7763646f626a313936302d30342d3136075060a4f54d4e304332be33ad78b1eafa4b"
        self.valid_success_response = {
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
            "verified": True
        } 
        self.valid_success_uuid = "urn:uuid:60a4f54d-4e30-4332-be33-ad78b1eafa4b"

    def test_add_base32_padding(self):
        self.assertEqual(verifier.add_base32_padding("JBSWY3DPEBLW64TMMQQQ"), 
                         "JBSWY3DPEBLW64TMMQQQ====")
        self.assertEqual(verifier.add_base32_padding("KRSXG5BB"), 
                         "KRSXG5BB")

    def test_check_and_remove_prefix(self):
        self.assertEqual(verifier.check_and_remove_prefix("NZCP:/1/ABCDEF"), 
                         "1/ABCDEF")
        self.assertFalse(verifier.check_and_remove_prefix("NZPP:/1/ABCDEF"))
        self.assertFalse(verifier.check_and_remove_prefix("NZCP::/1/ABCDEF"))
        self.assertFalse(verifier.check_and_remove_prefix(1))
        self.assertFalse(verifier.check_and_remove_prefix(""))

    def test_check_and_remove_version(self):
        self.assertEqual(verifier.check_and_remove_version("1/ABCDEF"), 
                         "ABCDEF")
        self.assertFalse(verifier.check_and_remove_version("0/ABCDEF"))
        self.assertFalse(verifier.check_and_remove_version("2/ABCDEF"))
        self.assertFalse(verifier.check_and_remove_version("1ABCDEF"))
        self.assertFalse(verifier.check_and_remove_version(""))

    def test_decode_base32(self):
        self.assertEqual(verifier.decode_base32("JBSWY3DPEBLW64TMMQQQ===="), b"Hello World!")
        self.assertFalse(verifier.decode_base32(""))
        self.assertFalse(verifier.decode_base32("111111111"))

    def test_decode_cbor(self):
        self.assertEqual(verifier.decode_cbor(bytes.fromhex(self.valid_encoded_headers)), self.valid_cbor_protected_headers)
        self.assertEqual(verifier.decode_cbor(bytes.fromhex(self.valid_cbor_payload_in_hex)), self.valid_cbor_payload) 
        self.assertFalse(verifier.decode_cbor("a1b2c3d4e5f6"))
        self.assertFalse(verifier.decode_cbor(""))
        self.assertFalse(verifier.decode_cbor(bytes.fromhex("a1b2c3d4e5f6")))

    def test_check_cwt_claims(self):
        self.assertTrue(verifier.check_cwt_claims(self.valid_cbor_payload)) 

        missing_issuer = {i:self.valid_cbor_payload[i] for i in self.valid_cbor_payload if i!=1} 
        self.assertFalse(verifier.check_cwt_claims(missing_issuer))

        issuer_not_trusted = self.valid_cbor_payload.copy()
        issuer_not_trusted[1] = "did:web:nzcp.covid19.govt.nz"
        self.assertFalse(verifier.check_cwt_claims(issuer_not_trusted))

        missing_nbf_date = {i:self.valid_cbor_payload[i] for i in self.valid_cbor_payload if i!=5}
        self.assertFalse(verifier.check_cwt_claims(missing_nbf_date))

        missing_exp_date = {i:self.valid_cbor_payload[i] for i in self.valid_cbor_payload if i!=4}
        self.assertFalse(verifier.check_cwt_claims(missing_exp_date))

        missing_vc = {i:self.valid_cbor_payload[i] for i in self.valid_cbor_payload if i!='vc'}
        self.assertFalse(verifier.check_cwt_claims(missing_vc))

        exp_date_in_past = self.valid_cbor_payload.copy()
        exp_date_in_past[4] = 1605171212
        self.assertFalse(verifier.check_cwt_claims(exp_date_in_past))

        nbf_date_in_future = self.valid_cbor_payload.copy()
        nbf_date_in_future[5] = 7979590593
        self.assertFalse(verifier.check_cwt_claims(nbf_date_in_future))

        self.assertFalse(verifier.check_cwt_claims({}))

    def test_decode_UUID(self):
        self.assertEqual(verifier.decode_UUID(bytes.fromhex(self.valid_uuid_hex)), self.valid_uuid)
        self.assertFalse(verifier.decode_UUID(bytes.fromhex("f81d4fae7dec11d0a76500a0c91e6b")))
        self.assertFalse(verifier.decode_UUID(""))
        self.assertFalse(verifier.decode_UUID("f81d4fae7dec11d0a76500a0c91e6bf6"))

    def test_get_DID_from_issuer(self):
        self.assertEqual(verifier.get_DID_from_issuer("did:web:nzcp.covid19.health.nz"), self.valid_did)
        self.assertEqual(verifier.stored_dids["did:web:nzcp.covid19.health.nz"], self.valid_did)
        self.assertFalse(verifier.get_DID_from_issuer("did:web:nzcp.covid19.govt.nz"))
        self.assertFalse(verifier.get_DID_from_issuer(""))
    
    def test_validate_DID(self):
        self.assertTrue(verifier.validate_DID(self.valid_cbor_payload[1],
                                              self.valid_cbor_protected_headers,
                                              self.valid_did))

        headers_incorrect_keyid = self.valid_cbor_protected_headers.copy()
        headers_incorrect_keyid[4] = "f87dec"
        self.assertFalse(verifier.validate_DID(self.valid_cbor_payload[1], 
                                               headers_incorrect_keyid, 
                                               self.valid_did))
        
        did_wrong_assertion_method = self.valid_did.copy()
        did_wrong_assertion_method["assertionMethod"] = []
        self.assertFalse(verifier.validate_DID(self.valid_cbor_payload[1],
                                               self.valid_cbor_protected_headers, 
                                               did_wrong_assertion_method))

        self.assertFalse(verifier.validate_DID("", {}, {}))

    def test_get_issuer_public_key_from_did(self):
        self.assertEqual(verifier.get_issuer_public_key_from_did(self.valid_did), self.valid_public_key)
        self.assertFalse(verifier.get_issuer_public_key_from_did(""))

        missing_public_key = self.valid_did.copy()
        missing_public_key["verificationMethod"][0] = {}
        self.assertFalse(verifier.get_issuer_public_key_from_did(missing_public_key))
        
    def test_convert_jwk_to_pem(self):
        self.assertEqual(verifier.convert_jwk_to_pem(self.valid_public_key), self.valid_pem_key)
        self.assertFalse(verifier.convert_jwk_to_pem({}))

    def test_generate_sig_structure(self):
        self.assertEqual(verifier.generate_sig_structure(self.valid_decoded_cose_struct[0], 
                                                         self.valid_decoded_cose_struct[2]).hex(), 
                         self.valid_sig_struct)

    def test_validate_signature(self):
        self.assertTrue(verifier.validate_signature(self.valid_decoded_cose_struct[3], 
                                                    self.valid_pem_key, 
                                                    bytes.fromhex(self.valid_sig_struct))) 

        incorrect_signature = b'\xd2\xe0{\x1d\xd7&=\x831f\xbd\xbbO\x1a\t87\xa9\x05\xd6\xec\xa2\xee\x83kk*\xda#\xc21T\xfb\xa8\x8aR\x9fg]f\x86\xeec+\t\xecX\x1a\xb0\x8fr\xb4X\x90K\xb39m\x10\xfaf\xd1\x14w'
        self.assertFalse(verifier.validate_signature(incorrect_signature,
                                                     self.valid_pem_key,
                                                     bytes.fromhex(self.valid_sig_struct)))
        
        self.assertFalse(verifier.validate_signature("this", "should", "fail"))
        self.assertFalse(verifier.validate_signature(["so"], {"should": None}, b"This"))

    def test_construct_response(self):
        self.assertEqual(verifier.construct_response(True, 
                                                     self.valid_cbor_payload, 
                                                     self.valid_success_uuid), 
                         self.valid_success_response)
        self.assertEqual(verifier.construct_response(False), {"verified": False})
        self.assertEqual(verifier.construct_response(True), {"verified": False})


class TestVerifier(unittest.TestCase):
    
    def setUp(self):
        self.test_codes = {
            "VALID_CODE": "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX",
            "BAD_PUBLIC_KEY": "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAY73U6TCQ3KF5KFML5LRCS5D3PCYIB2D3EOIIZRPXPUA2OR3NIYCBMGYRZUMBNBDMIA5BUOZKVOMSVFS246AMU7ADZXWBYP7N4QSKNQ4TETIF4VIRGLHOXWYMR4HGQ7KYHHU",
            "PUBLIC_KEY_NOT_FOUND": "NZCP:/1/2KCEVIQEIVVWK6JNGIASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVBMP3LEDMB4CLBS2I7IOYJZW46U2YIBCSOFZMQADVQGM3JKJBLCY7ATASDTUYWIP4RX3SH3IFBJ3QWPQ7FJE6RNT5MU3JHCCGKJISOLIMY3OWH5H5JFUEZKBF27OMB37H5AHF",
            "MODIFIED_SIGNATURE": "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIAAAAAAAAAAAAAAAAC63WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX",
            "MODIFIED_PAYLOAD": "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEOKKALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWKU3UMV3GK2TGMFWWS3DZJZQW2ZLDIRXWKY3EN5RGUMJZGYYC2MBUFUYTMB2QMCSPKTKOGBBTFPRTVV4LD2X2JNMEAAAAAAAAAAAAAAAABPN3J4NASOBXVEC5P3FC52BWW2ZK3IR4EMKU7OUIUUU7M5OWNBXOMMVQT3CYDKYI64VULCIEXMZZNUIPUZWRCR3Q",
            "EXPIRED_PASS": "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUX5AM2FQIGTBPBPYWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA56TNJCCUN2NVK5NGAYOZ6VIWACYIBM3QXW7SLCMD2WTJ3GSEI5JH7RXAEURGATOHAHXC2O6BEJKBSVI25ICTBR5SFYUDSVLB2F6SJ63LWJ6Z3FWNHOXF6A2QLJNUFRQNTRU",
            "NOT_ACTIVE_PASS": "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRU2XI5UFQIGTMZIQIWYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVA27NR3GFF4CCGWF66QGMJSJIF3KYID3KTKCBUOIKIC6VZ3SEGTGM3N2JTWKGDBAPLSG76Q3MXIDJRMNLETOKAUTSBOPVQEQAX25MF77RV6QVTTSCV2ZY2VMN7FATRGO3JATR"
        }
        self.success_response = {
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
            "verified": True
        } 
        self.fail_response = {"verified": False}

    def test_check_code(self):
        self.assertEqual(verifier.check_code(self.test_codes["VALID_CODE"]), self.success_response)
        self.assertEqual(verifier.check_code(self.test_codes["BAD_PUBLIC_KEY"]), self.fail_response)
        self.assertEqual(verifier.check_code(self.test_codes["PUBLIC_KEY_NOT_FOUND"]), self.fail_response)
        self.assertEqual(verifier.check_code(self.test_codes["MODIFIED_SIGNATURE"]), self.fail_response)
        self.assertEqual(verifier.check_code(self.test_codes["MODIFIED_PAYLOAD"]), self.fail_response)
        self.assertEqual(verifier.check_code(self.test_codes["EXPIRED_PASS"]), self.fail_response)
        self.assertEqual(verifier.check_code(self.test_codes["NOT_ACTIVE_PASS"]), self.fail_response)
        self.assertEqual(verifier.check_code("NZCP:/1/MEMES"), self.fail_response)
        self.assertEqual(verifier.check_code("NOT EVEN CLOSE TO A CORRECT PASS"), self.fail_response)
        self.assertEqual(verifier.check_code(""), self.fail_response)


if __name__ == '__main__':
    unittest.main()
