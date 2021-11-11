import unittest
import verifier

class TestVerifierFunctions(unittest.TestCase):

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
        self.assertEqual(verifier.decode_base32("JBSWY3DPEBLW64TMMQQQ===="), 
                         b"Hello World!")
        self.assertFalse(verifier.decode_base32(""))
        self.assertFalse(verifier.decode_base32("111111111"))

    def test_decode_cbor(self):
        self.assertEqual(verifier.decode_cbor(bytes.fromhex("a204456b65792d310126")), 
                         {4: b'key-1', 1: -7})
        self.assertEqual(verifier.decode_cbor(bytes.fromhex("a501781e6469643a7765623a6e7a63702e636f76696431392e6865616c74682e6e7a051a61819a0a041a7450400a627663a46840636f6e7465787482782668747470733a2f2f7777772e77332e6f72672f323031382f63726564656e7469616c732f7631782a68747470733a2f2f6e7a63702e636f76696431392e6865616c74682e6e7a2f636f6e74657874732f76316776657273696f6e65312e302e306474797065827456657269666961626c6543726564656e7469616c6f5075626c6963436f766964506173737163726564656e7469616c5375626a656374a369676976656e4e616d65644a61636b6a66616d696c794e616d656753706172726f7763646f626a313936302d30342d3136075060a4f54d4e304332be33ad78b1eafa4b")), {1: 'did:web:nzcp.covid19.health.nz', 5: 1635883530, 4: 1951416330, 'vc': {'@context': ['https://www.w3.org/2018/credentials/v1', 'https://nzcp.covid19.health.nz/contexts/v1'], 'version': '1.0.0', 'type': ['VerifiableCredential', 'PublicCovidPass'], 'credentialSubject': {'givenName': 'Jack', 'familyName': 'Sparrow', 'dob': '1960-04-16'}}, 7: b'`\xa4\xf5MN0C2\xbe3\xadx\xb1\xea\xfaK'})
        self.assertFalse(verifier.decode_cbor("a1b2c3d4e5f6"))
        self.assertFalse(verifier.decode_cbor(""))
        self.assertFalse(verifier.decode_cbor(bytes.fromhex("a1b2c3d4e5f6")))

        # TODO - test the rest!
        # TODO - test examples from the spec!


if __name__ == '__main__':
    unittest.main()