"""Extends asn1crypto with CRMF"""
from asn1crypto import cms as asn1_cms
from asn1crypto import algos as asn1_algos
from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509


class PKMACValue(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("algId", asn1_algos.AlgorithmIdentifier),
        ("value", asn1_cms.BitString),
    ]


class AuthInfo(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        # used only if an authenticated identity has been
        # established for the sender(e.g., a DN from a
        # previously-issued and currently-valid certificate)
        ("sender", asn1_cms.GeneralName, {"implicit": 0}),
        # used if no authenticated GeneralName currently exists for
        # the sender; publicKeyMAC contains a password-based MAC
        # on the DER-encoded value of publicKey
        ("publicKeyMAC", PKMACValue),
    ]


class CertId(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("issuer", asn1_cms.GeneralName),
        ("serialNumber", asn1_cms.Integer),
    ]


class POPOSigningKeyInput(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("authinfo", AuthInfo),
        ("publicKey", asn1_keys.PublicKeyInfo),
    ]


class POPOSigningKey(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("poposkInput", POPOSigningKeyInput, {"implicit": 0, "optional": True}),
        ("algorithmIdentifier", asn1_algos.AlgorithmIdentifier),
        ("signature", asn1_cms.BitString),
    ]


class Identifier(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        ("string", asn1_cms.UTF8String),
        ("generalName", asn1_cms.GeneralName),
    ]


class EncKeyWithID(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("privateKey", asn1_keys.PrivateKeyInfo),
        ("identifier", Identifier, {"optional": True}),
    ]


class PBMParameter(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("salt", asn1_cms.OctetString),
        ("owf", asn1_algos.AlgorithmIdentifier),
        ("iterationCount", asn1_cms.Integer),
        ("mac", asn1_algos.AlgorithmIdentifier),
    ]


class SubsequentMessage(asn1_cms.Integer):  # type: ignore
    _map = {
        0: "encrCert",
        1: "challengeResp",
    }


class EncryptedValue(asn1_cms.Sequence):  # type: ignore
    _fields = [
        # the intended algorithm for which the value will be used
        ("intendedAlg", asn1_algos.AlgorithmIdentifier, {"implicit": 0, "optional": True}),
        # the symmetric algorithm used to encrypt the value
        ("symmAlg", asn1_algos.AlgorithmIdentifier, {"implicit": 1, "optional": True}),
        # the (encrypted) symmetric key used to encrypt the value
        ("encSymmKey", asn1_cms.BitString, {"implicit": 2, "optional": True}),
        # algorithm used to encrypt the symmetric key
        ("keyAlg", asn1_algos.AlgorithmIdentifier, {"implicit": 3, "optional": True}),
        # a brief description or identifier of the encValue content
        # (may be meaningful only to the sending entity, and used only
        # if EncryptedValue might be re-examined by the sending entity
        # in the future)
        ("valueHint", asn1_cms.OctetString, {"implicit": 4, "optional": True}),
        # The use of the EncryptedValue field has been deprecated in favor
        # of the EnvelopedData structure
        ("encValue", asn1_cms.BitString),  # Deprecated
    ]


class EncryptedKey(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        ("encryptedValue", EncryptedValue),  # Deprecated
        # The encrypted private key MUST be placed in the envelopedData
        # encryptedContentInfo encryptedContent OCTET STRING.
        ("envelopedData", asn1_cms.EnvelopedData, {"implicit": 0}),
    ]


class PKIArchiveOptions(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        # the actual value of the private key
        ("encryptedPrivKey", EncryptedKey, {"implicit": 0}),
        # parameters which allow the private key to be re-generated
        ("keyGenParameters", asn1_cms.OctetString, {"implicit": 1}),
        # set to TRUE if sender wishes receiver to archive the private
        # key of a key pair that the receiver generates in response to
        # this request; set to FALSE if no archival is desired.
        ("archiveRemGenPrivKey", asn1_x509.Boolean, {"implicit": 2}),
    ]


class POPOPrivKey(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        ("thisMessage", asn1_cms.BitString, {"implicit": 0}),  # deprecated
        ("subsequentMessage", SubsequentMessage, {"implicit": 1}),
        ("dhMAC", asn1_cms.BitString, {"implicit": 2}),  # deprecated
        ("agreeMAC", PKMACValue, {"implicit": 3}),
        # for keyAgreement (only), possession is
        # (which contains a MAC (over the DER-encoded value of the
        # certReq parameter in CertReqMsg, which must include both subject
        # and publicKey) based on a key derived from the end entity's
        # private DH key and the CA's public DH key);
        # the dhMAC value MUST be calculated as per the directions given
        # in RFC 2875 for static DH proof-of-possession.
        ("encryptedKey", asn1_cms.EnvelopedData, {"implicit": 4}),
    ]


class ProofOfPossession(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        ("raVerified", asn1_x509.Null, {"explicit": 0}),
        ("signature", POPOSigningKey, {"explicit": 1}),
        ("keyEncipherment", POPOPrivKey, {"explicit": 2}),
        ("keyAgreement", POPOPrivKey, {"explicit": 3}),
    ]
