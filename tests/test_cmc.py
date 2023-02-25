"""
Test CMC
"""
import unittest
import base64

from asn1crypto import cms as asn1_cms

from src.python_cmc.cmc import PKIData


class TestCMC(unittest.TestCase):
    """
    Test cmc
    """

    def test_cmc_requests(self) -> None:
        """
        Test cmc requests
        """

        request_list = (
            "MIIFTgYJKoZIhvcNAQcCoIIFPzCCBTsCAQMxDTALBglghkgBZQMEAgEwggLUBggrBgEFBQcMAqCCAsYEggLCMIICvjCB1zCBlgIEDgTXoQYIKwYBBQUHBwYxgYMEgYC3Rw6WmoJA8VQOnb8uzODY+og6LIMWTMIiRkwPyZdje3UQ3OZ4C5dN220IFHo9r+/rzrS3M3q0xQUZwOXltkLYNYKZqrDLVbh79VwkdY2JtA304RvjeH3S5AMpJvsW4XT70MTAQ6HCwrpunIWE9epfOe3p1z2NC0MRfDfC9Qg1XjAYAgQeYyg3BggrBgEFBQcHEjEGBARjcm1mMCICBFz3WzAGCCsGAQUFBwcLMRAwDgIELp/WpzAGAgR/4SGvMIIB3KGCAdgwggHUAgR/4SGvMIIByqVzMHExCzAJBgNVBAYTAlNFMSYwJAYDVQQDDB1EYXRlIE5hbWUgMjAyMy0wMS0zMCAxNzoxMTo0MjETMBEGA1UEBRMKMTIzNDU2Nzg5MDEPMA0GA1UECgwGQVAgT3JnMRQwEgYDVQQLDAtBUCBPcmcgVW5pdKZZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBiMSIFZZg8e4K7H0opmZAKd4cNrD4WX64208PHitkfTfu0oa5n8zB/zcV20IMuzJiY0TlTVlOjijxdF/3+57YapgfcwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRLk79GlfrsxADdYc7cnJitGY1BlDApBgNVHQ4EIgQgFODwYpm21NCZsPjcRDyjpEjdo4Lv4iQL1of0RHScqOQwDgYDVR0PAQH/BAQDAgOIMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9wa2NzMTEtY2Euc3VuZXQuc2U6ODAwNS9jcmwwMTBABggrBgEFBQcBAQQ0MDIwMAYIKwYBBQUHMAGGJGh0dHA6Ly9wa2NzMTEtY2Euc3VuZXQuc2U6ODAwNS9vY3NwLzAVBgNVHSAEDjAMMAoGCCqFcAECAWQBMAAwAKCCASgwggEkMIHKoAMCAQICBGF8NSowCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MB4XDTIxMTAyOTE3NTM0NloXDTI2MTAyOTE3NTM0NlowGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm5YZkVj1TwoPxGwgAsIlgSVIfgaAjr+djovlFM8Z1iXnHMXbJgpGUVAE1VsHfn0cGZpW6G4ptOQuIqxNPLSpEzAKBggqhkjOPQQDAgNJADBGAiEAiK1uTHrROyodlseT2Sj6iMVDddYnTNNooZBx+CWtNT8CIQCMmzcu47UXobEOOCktVWn67vnStULCxQnMirDyTjK0hjGCASEwggEdAgEBMCIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50AgRhfDUqMAsGCWCGSAFlAwQCAaCBkjAXBgkqhkiG9w0BCQMxCgYIKwYBBQUHDAIwHAYJKoZIhvcNAQkFMQ8XDTIzMDEzMDE2MTE0MlowKAYJKoZIhvcNAQk0MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIK4iaq8/Q2BYFaGVnublUQWsnyn0RWf0o5xDi/fKUjmNMAoGCCqGSM49BAMCBEYwRAIgfFrYzIk2oCHJGc/NCM7i95pORUVQLcdToEYXhtZRKSUCIBWj3rMXblpGmCJV7TpjrHzf9KYhNZOGiwJcJXfB60xi",  # pylint: disable=line-too-long
            """MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQMxDTALBglghkgBZQMEAgEwggMlBggrBgEFBQcMAqCCAxcEggMTMIIDDzCBtTCBlgIEFEyxWQYIKwYBBQUHBwYxgYMEgYBTw2alTy8Vtv4HIgT+uvKUSPQErO12lpXnWc/MXVTgZICa2IfeamKx7y6Q2pYjT5C0Wux+sq3EWsu1vgqMmqjNBPAxWaTwCmcDPqWXqR+VFQeEm0aQErAVKyaARusXeFgXBGz28sTKiVy08gsjdnvdX0AV/pkR8TBvufIN+GCJkTAaAgQ325qWBggrBgEFBQcHEjEIBAZwa2NzMTAwggJPoIICSwIERqu1/jCCAkEwggHmAgEAMHExCzAJBgNVBAYTAlNFMSYwJAYDVQQDDB1EYXRlIE5hbWUgMjAyMy0wMS0zMCAyMzoxODo0MzETMBEGA1UEBRMKMTIzNDU2Nzg5MDEPMA0GA1UECgwGQVAgT3JnMRQwEgYDVQQLDAtBUCBPcmcgVW5pdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKieki4N5PlfUBhcGF1FHn9CzpufPCHNTCPAMYcJBGLExbSxQTUB6me69AXL5v1SNfFBp8SALU23MqrrZT22yx+gggERMIIBDQYJKoZIhvcNAQkOMYH/MIH8MAkGA1UdEwQCMAAwKwYDVR0jBCQwIoAgXUejgI1+8HlK5UXdC+XRiUp7nLV1X+W8LZAEroxOH/AwKQYDVR0OBCIEIH9PzrbnQ9UgNmfdI3eXypa5ZVeU2kpprRp09QrfbNYKMA4GA1UdDwEB/wQEAwIDiDAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vbG9jYWxob3N0OjgwODAvY3JsL2NhMDEuY3JsMDsGCCsGAQUFBwEBBC8wLTArBggrBgEFBQcwAYYfaHR0cDovL2xvY2FsaG9zdDo4MDgwL29jc3AvY2EwMTAVBgNVHSAEDjAMMAoGCCqFcAECAWQBMAoGCCqGSM49BAMCA0kAMEYCIQDId5LSygFHg+kOWmM3pKvXKWhUKZP7Eh5vmNhGWTb7vAIhAIiJgC7oM5pexJk8jDpVBxoXW0hFfKZ9iPP6sPmWs8NfMAAwAKCCASgwggEkMIHKoAMCAQICBGF8NSowCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MB4XDTIxMTAyOTE3NTM0NloXDTI2MTAyOTE3NTM0NlowGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm5YZkVj1TwoPxGwgAsIlgSVIfgaAjr+djovlFM8Z1iXnHMXbJgpGUVAE1VsHfn0cGZpW6G4ptOQuIqxNPLSpEzAKBggqhkjOPQQDAgNJADBGAiEAiK1uTHrROyodlseT2Sj6iMVDddYnTNNooZBx+CWtNT8CIQCMmzcu47UXobEOOCktVWn67vnStULCxQnMirDyTjK0hjGCASMwggEfAgEBMCIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50AgRhfDUqMAsGCWCGSAFlAwQCAaCBkjAXBgkqhkiG9w0BCQMxCgYIKwYBBQUHDAIwHAYJKoZIhvcNAQkFMQ8XDTIzMDEzMDIyMTg0M1owKAYJKoZIhvcNAQk0MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIN1KSwme0J370cFtI4dncah8Vr5cMzgsDYN5qehyxUJsMAoGCCqGSM49BAMCBEgwRgIhAJhaJ2V8z7vQRVhK1l4p2f6YihPzM/ygOSxE2ckgSw25AiEA3ffDb6q4ys6urVxy00MB5xhNzS6aWtkap5j77+rxG9U=""",  # pylint: disable=line-too-long
            """MIIFTgYJKoZIhvcNAQcCoIIFPzCCBTsCAQMxDTALBglghkgBZQMEAgEwggLUBggrBgEFBQcMAqCCAsYEggLCMIICvjCB1zCBlgIEDgTXoQYIKwYBBQUHBwYxgYMEgYC3Rw6WmoJA8VQOnb8uzODY+og6LIMWTMIiRkwPyZdje3UQ3OZ4C5dN220IFHo9r+/rzrS3M3q0xQUZwOXltkLYNYKZqrDLVbh79VwkdY2JtA304RvjeH3S5AMpJvsW4XT70MTAQ6HCwrpunIWE9epfOe3p1z2NC0MRfDfC9Qg1XjAYAgQeYyg3BggrBgEFBQcHEjEGBARjcm1mMCICBFz3WzAGCCsGAQUFBwcLMRAwDgIELp/WpzAGAgR/4SGvMIIB3KGCAdgwggHUAgR/4SGvMIIByqVzMHExCzAJBgNVBAYTAlNFMSYwJAYDVQQDDB1EYXRlIE5hbWUgMjAyMy0wMS0zMCAxNzoxMTo0MjETMBEGA1UEBRMKMTIzNDU2Nzg5MDEPMA0GA1UECgwGQVAgT3JnMRQwEgYDVQQLDAtBUCBPcmcgVW5pdKZZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBiMSIFZZg8e4K7H0opmZAKd4cNrD4WX64208PHitkfTfu0oa5n8zB/zcV20IMuzJiY0TlTVlOjijxdF/3+57YapgfcwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRLk79GlfrsxADdYc7cnJitGY1BlDApBgNVHQ4EIgQgFODwYpm21NCZsPjcRDyjpEjdo4Lv4iQL1of0RHScqOQwDgYDVR0PAQH/BAQDAgOIMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9wa2NzMTEtY2Euc3VuZXQuc2U6ODAwNS9jcmwwMTBABggrBgEFBQcBAQQ0MDIwMAYIKwYBBQUHMAGGJGh0dHA6Ly9wa2NzMTEtY2Euc3VuZXQuc2U6ODAwNS9vY3NwLzAVBgNVHSAEDjAMMAoGCCqFcAECAWQBMAAwAKCCASgwggEkMIHKoAMCAQICBGF8NSowCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MB4XDTIxMTAyOTE3NTM0NloXDTI2MTAyOTE3NTM0NlowGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm5YZkVj1TwoPxGwgAsIlgSVIfgaAjr+djovlFM8Z1iXnHMXbJgpGUVAE1VsHfn0cGZpW6G4ptOQuIqxNPLSpEzAKBggqhkjOPQQDAgNJADBGAiEAiK1uTHrROyodlseT2Sj6iMVDddYnTNNooZBx+CWtNT8CIQCMmzcu47UXobEOOCktVWn67vnStULCxQnMirDyTjK0hjGCASEwggEdAgEBMCIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50AgRhfDUqMAsGCWCGSAFlAwQCAaCBkjAXBgkqhkiG9w0BCQMxCgYIKwYBBQUHDAIwHAYJKoZIhvcNAQkFMQ8XDTIzMDEzMDE2MTE0MlowKAYJKoZIhvcNAQk0MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIK4iaq8/Q2BYFaGVnublUQWsnyn0RWf0o5xDi/fKUjmNMAoGCCqGSM49BAMCBEYwRAIgfFrYzIk2oCHJGc/NCM7i95pORUVQLcdToEYXhtZRKSUCIBWj3rMXblpGmCJV7TpjrHzf9KYhNZOGiwJcJXfB60xi""",  # pylint: disable=line-too-long
            """MIIEJgYJKoZIhvcNAQcCoIIEFzCCBBMCAQMxDTALBglghkgBZQMEAgEwggGrBggrBgEFBQcMAqCCAZ0EggGZMIIBlTCCAYswgZYCBC3kedoGCCsGAQUFBwcGMYGDBIGAVwfchpQ55okeyLF93LzMgGvnVa37GyIaszVm2DTmEqxxlqPliOKKsYuaxJcWO6IqRdyaLO6uv6BA1D5gU1M9k1fgjVZ05JFly0/XckmbwZsBOgwPiiKTyI4A1l1XxOg8NlOeMYfXZ05Tm2pDkmBE8ek8vZMVF0hsi8L+27HYrewwge8CBCF9/W0GCCsGAQUFBwcRMYHcMIHZMIGvMQswCQYDVQQGEwJTRTEuMCwGA1UECgwlTXluZGlnaGV0ZW4gZsO2ciBkaWdpdGFsIGbDtnJ2YWx0bmluZzEUMBIGA1UECwwLSGVhZGxlc3MgQ0ExFDASBgNVBGEMCzIwMjEwMC02ODgzMUQwQgYDVQQDDDtESUdHIFNpZ25hdHVyZSB2YWxpZGF0aW9uIHRydXN0IENBIC0gRVUgQ0EgYW5kIFRTQSBTZXJ2aWNlcwIRANKZIMmiIj1KBtI97oGaEBoKAQYYDzIwMjMwMTMwMjE0NTQyWjAAMAAwAKCCASgwggEkMIHKoAMCAQICBGF8NSowCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MB4XDTIxMTAyOTE3NTM0NloXDTI2MTAyOTE3NTM0NlowGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm5YZkVj1TwoPxGwgAsIlgSVIfgaAjr+djovlFM8Z1iXnHMXbJgpGUVAE1VsHfn0cGZpW6G4ptOQuIqxNPLSpEzAKBggqhkjOPQQDAgNJADBGAiEAiK1uTHrROyodlseT2Sj6iMVDddYnTNNooZBx+CWtNT8CIQCMmzcu47UXobEOOCktVWn67vnStULCxQnMirDyTjK0hjGCASIwggEeAgEBMCIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50AgRhfDUqMAsGCWCGSAFlAwQCAaCBkjAXBgkqhkiG9w0BCQMxCgYIKwYBBQUHDAIwHAYJKoZIhvcNAQkFMQ8XDTIzMDEzMDIxNDU0MlowKAYJKoZIhvcNAQk0MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIGdxWJ+kbJwD6vwTu099C8N3do2n4FhOGiWOTvWpL2gLMAoGCCqGSM49BAMCBEcwRQIhAJFZKiriik2tAuewi+uvZUaMYxbJ0/rHMsaMx8sVcM1YAiA+ShaOHc+92ylJtz9we8McmE61sswad7xuWj+qtkxXQA==""",  # pylint: disable=line-too-long
            """MIIFUwYJKoZIhvcNAQcCoIIFRDCCBUACAQMxDTALBglghkgBZQMEAgEwggLZBggrBgEFBQcMAqCCAssEggLHMIICwzCB1zCBlgIESUvmzAYIKwYBBQUHBwYxgYMEgYA0HycpETeGmY81Vgs6HQPTJILKc6vRo80OjRH+yLb7z9Pq9dUnWOUhN4zs7sWN64yjDNM+kvVv9+Nm1XpQ99t3cWkjc3WzOOgoiwiGMLdZaqZipfuC0tYV9bPEfbL7ggv/Oa9BiM8NTg8t1Z7O+hJkPeVM66orh8uoB75I4G59HzAYAgQ1mgbtBggrBgEFBQcHEjEGBARjcm1mMCICBFoGN74GCCsGAQUFBwcLMRAwDgIEWZphMTAGAgQchku4MIIB4aGCAd0wggHZAgQchku4MIIBz6VzMHExCzAJBgNVBAYTAlNFMSYwJAYDVQQDDB1EYXRlIE5hbWUgMjAyMy0wMS0xMSAxMzozMjo0MjETMBEGA1UEBRMKMTIzNDU2Nzg5MDEPMA0GA1UECgwGQVAgT3JnMRQwEgYDVQQLDAtBUCBPcmcgVW5pdKZZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDVAdItFB+4+w8LbzDRZZL5mkIITDpgtdr1KMtF/6hb9CwWAB0vphsPBCsuNchoFZhJLxmLzv5Q+xNEcG72rRbOpgfwwCQYDVR0TBAIwADArBgNVHSMEJDAigCBdR6OAjX7weUrlRd0L5dGJSnuctXVf5bwtkASujE4f8DApBgNVHQ4EIgQgA3rg7ywNY3HlSfV1tXd6KGAxPyKtZyQ7F4KJZHB3IFkwDgYDVR0PAQH/BAQDAgOIMDMGA1UdHwQsMCowKKAmoCSGImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9jcmwvY2EwMS5jcmwwOwYIKwYBBQUHAQEELzAtMCsGCCsGAQUFBzABhh9odHRwOi8vbG9jYWxob3N0OjgwODAvb2NzcC9jYTAxMBUGA1UdIAQOMAwwCgYIKoVwAQIBZAEwADAAoIIBKDCCASQwgcqgAwIBAgIEYXw1KjAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9UZXN0IENNQyBDbGllbnQwHhcNMjExMDI5MTc1MzQ2WhcNMjYxMDI5MTc1MzQ2WjAaMRgwFgYDVQQDDA9UZXN0IENNQyBDbGllbnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASblhmRWPVPCg/EbCACwiWBJUh+BoCOv52Oi+UUzxnWJeccxdsmCkZRUATVWwd+fRwZmlbobim05C4irE08tKkTMAoGCCqGSM49BAMCA0kAMEYCIQCIrW5MetE7Kh2Wx5PZKPqIxUN11idM02ihkHH4Ja01PwIhAIybNy7jtRehsQ44KS1Vafru+dK1QsLFCcyKsPJOMrSGMYIBITCCAR0CAQEwIjAaMRgwFgYDVQQDDA9UZXN0IENNQyBDbGllbnQCBGF8NSowCwYJYIZIAWUDBAIBoIGSMBcGCSqGSIb3DQEJAzEKBggrBgEFBQcMAjAcBgkqhkiG9w0BCQUxDxcNMjMwMTExMTIzMjQyWjAoBgkqhkiG9w0BCTQxGzAZMAsGCWCGSAFlAwQCAaEKBggqhkjOPQQDAjAvBgkqhkiG9w0BCQQxIgQgUdqYlBQZB3tADk+Zw0gzs1xuoJe82Z3a6jGCkc/EAmIwCgYIKoZIzj0EAwIERjBEAiA5yd/rQaBhYfmXI0gb5LSgw27ipM5hFmWcI6Y/DuR3KQIgUrjFdfQbdqfwANUlrVUOiIH0xiJbSzvKc3HEF7cEImc=""",  # pylint: disable=line-too-long
        )

        for req in request_list:
            data = base64.b64decode(req)
            info = asn1_cms.ContentInfo.load(data)
            pkidata = PKIData.load(info["content"]["encap_content_info"]["content"].parsed.dump())
            self.assertTrue(isinstance(pkidata, PKIData))
            _ = pkidata.native