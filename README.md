Extends asn1crypto with CMC and CRMF - https://www.rfc-editor.org/rfc/rfc5272

## To run, deploy, test and everything run
``` bash
bash dev-run.sh
```

``` python
import base64
from asn1crypto import cms as asn1_cms
from python_cmc.cmc import PKIData

request = "MIIFTgYJKoZIhvcNAQcCoIIFPzCCBTsCAQMxDTALBglghkgBZQMEAgEwggLUBggrBgEFBQcMAqCCAsYEggLCMIICvjCB1zCBlgIEDgTXoQYIKwYBBQUHBwYxgYMEgYC3Rw6WmoJA8VQOnb8uzODY+og6LIMWTMIiRkwPyZdje3UQ3OZ4C5dN220IFHo9r+/rzrS3M3q0xQUZwOXltkLYNYKZqrDLVbh79VwkdY2JtA304RvjeH3S5AMpJvsW4XT70MTAQ6HCwrpunIWE9epfOe3p1z2NC0MRfDfC9Qg1XjAYAgQeYyg3BggrBgEFBQcHEjEGBARjcm1mMCICBFz3WzAGCCsGAQUFBwcLMRAwDgIELp/WpzAGAgR/4SGvMIIB3KGCAdgwggHUAgR/4SGvMIIByqVzMHExCzAJBgNVBAYTAlNFMSYwJAYDVQQDDB1EYXRlIE5hbWUgMjAyMy0wMS0zMCAxNzoxMTo0MjETMBEGA1UEBRMKMTIzNDU2Nzg5MDEPMA0GA1UECgwGQVAgT3JnMRQwEgYDVQQLDAtBUCBPcmcgVW5pdKZZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBiMSIFZZg8e4K7H0opmZAKd4cNrD4WX64208PHitkfTfu0oa5n8zB/zcV20IMuzJiY0TlTVlOjijxdF/3+57YapgfcwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRLk79GlfrsxADdYc7cnJitGY1BlDApBgNVHQ4EIgQgFODwYpm21NCZsPjcRDyjpEjdo4Lv4iQL1of0RHScqOQwDgYDVR0PAQH/BAQDAgOIMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9wa2NzMTEtY2Euc3VuZXQuc2U6ODAwNS9jcmwwMTBABggrBgEFBQcBAQQ0MDIwMAYIKwYBBQUHMAGGJGh0dHA6Ly9wa2NzMTEtY2Euc3VuZXQuc2U6ODAwNS9vY3NwLzAVBgNVHSAEDjAMMAoGCCqFcAECAWQBMAAwAKCCASgwggEkMIHKoAMCAQICBGF8NSowCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MB4XDTIxMTAyOTE3NTM0NloXDTI2MTAyOTE3NTM0NlowGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm5YZkVj1TwoPxGwgAsIlgSVIfgaAjr+djovlFM8Z1iXnHMXbJgpGUVAE1VsHfn0cGZpW6G4ptOQuIqxNPLSpEzAKBggqhkjOPQQDAgNJADBGAiEAiK1uTHrROyodlseT2Sj6iMVDddYnTNNooZBx+CWtNT8CIQCMmzcu47UXobEOOCktVWn67vnStULCxQnMirDyTjK0hjGCASEwggEdAgEBMCIwGjEYMBYGA1UEAwwPVGVzdCBDTUMgQ2xpZW50AgRhfDUqMAsGCWCGSAFlAwQCAaCBkjAXBgkqhkiG9w0BCQMxCgYIKwYBBQUHDAIwHAYJKoZIhvcNAQkFMQ8XDTIzMDEzMDE2MTE0MlowKAYJKoZIhvcNAQk0MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIK4iaq8/Q2BYFaGVnublUQWsnyn0RWf0o5xDi/fKUjmNMAoGCCqGSM49BAMCBEYwRAIgfFrYzIk2oCHJGc/NCM7i95pORUVQLcdToEYXhtZRKSUCIBWj3rMXblpGmCJV7TpjrHzf9KYhNZOGiwJcJXfB60xi"
data = base64.b64decode(request)
info = asn1_cms.ContentInfo.load(data)
pkidata = PKIData.load(info["content"]["encap_content_info"]["content"].parsed.dump())
print(pkidata.native)
```

## Coming soon
* Complete implementation
* More and better tests
