"""Extends asn1crypto with CMC and CRMF"""

from asn1crypto import cms as asn1_cms
from asn1crypto import crl as asn1_crl
from asn1crypto import csr as asn1_csr
from asn1crypto import x509 as asn1_x509
from asn1crypto import algos as asn1_algos
from asn1crypto import keys as asn1_keys


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


class SubsequentMessage(asn1_cms.Enumerated):  # type: ignore
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


class CertId(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("issuer", asn1_cms.GeneralName),
        ("serialNumber", asn1_cms.Integer),
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


class GetCert(asn1_cms.Sequence):  # type: ignore
    """RFC 5272 6.9. Get Certificate Control"""

    _fields = [
        ("issuerName", asn1_cms.GeneralName),
        ("serialNumber", asn1_cms.Integer),
    ]


class GetCRL(asn1_cms.Sequence):  # type: ignore
    """RFC 5272 6.10. Get CRL Control"""

    _fields = [
        ("issuerName", asn1_cms.Name),
        ("cRLName", asn1_cms.GeneralName, {"optional": True}),
        ("time", asn1_cms.GeneralizedTime, {"optional": True}),
        ("reasons", asn1_crl.ReasonFlags, {"optional": True}),
    ]


class RevokeRequest(asn1_cms.Sequence):  # type: ignore
    """RFC 5272 6.11. Revocation Request Control"""

    _fields = [
        ("issuerName", asn1_cms.Name),
        ("serialNumber", asn1_cms.Integer),
        ("reason", asn1_crl.CRLReason),
        ("invalidityDate", asn1_cms.GeneralizedTime, {"optional": True}),
        ("sharedSecret", asn1_cms.OctetString, {"optional": True}),
        ("comment", asn1_cms.UTF8String, {"optional": True}),
    ]


class BodyPartList(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = asn1_cms.Integer


class AnchorHashes(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = asn1_cms.OctetString


class PublishTrustAnchors(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("seqNumber", asn1_cms.Integer),
        ("hashAlgorithm", asn1_algos.AlgorithmIdentifier),
        ("anchorHashes", AnchorHashes),
    ]


class SinglePubInfoPubMethod(asn1_cms.Enumerated):  # type: ignore
    _map = {
        0: "dontCare",
        1: "x500",
        2: "web",
        3: "ldap",
    }


class SinglePubInfo(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("pubMethod", SinglePubInfoPubMethod),
        ("pubLocation", asn1_cms.GeneralName, {"optional": True}),
    ]


class SinglePubInfos(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = SinglePubInfo


class PKIPublicationInfoAction(asn1_cms.Enumerated):  # type: ignore
    _map = {
        0: "dontPublish",
        1: "pleasePublish",
    }


class PKIPublicationInfo(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("action", PKIPublicationInfoAction),
        # pubInfos MUST NOT be present if action is "dontPublish"
        # (if action is "pleasePublish" and pubInfos is omitted,
        # "dontCare" is assumed)
        ("pubInfos", SinglePubInfos, {"optional": True}),
    ]


class CertHashes(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = asn1_cms.OctetString


class CMCPublicationInfo(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("hashAlg", asn1_algos.AlgorithmIdentifier),
        ("certHashes", CertHashes),
        ("pubInfo", PKIPublicationInfo),
    ]


class TaggedContentInfo(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("bodyPartID", asn1_cms.Integer),
        ("contentInfo", asn1_cms.EncapsulatedContentInfo),
    ]


class TaggedContentInfos(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = TaggedContentInfo


class CMCStatus(asn1_cms.Enumerated):  # type: ignore
    # 1: 'reserved',
    _map = {
        0: "success",
        2: "failed",
        3: "pending",
        4: "noSupport",
        5: "confirmRequired",
        6: "popRequired",
        7: "partial",
    }


class CMCFailInfo(asn1_cms.Enumerated):  # type: ignore
    _map = {
        0: "badAlg",
        1: "badMessageCheck",
        2: "badRequest",
        3: "badTime",
        4: "badCertId",
        5: "unsupportedExt",
        6: "mustArchiveKeys",
        7: "badIdentity",
        8: "popRequired",
        9: "popFailed",
        10: "noKeyReuse",
        11: "internalCAError",
        12: "tryLater",
        13: "authDataFail",
    }


class PendInfo(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("pendToken", asn1_cms.OctetString),
        ("pendTime", asn1_cms.GeneralizedTime),
    ]


class ExtendedFailInfo(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("failInfoOID", asn1_cms.ObjectIdentifier),
        ("failInfoValue", asn1_cms.Any),
    ]


class BodyPartPath(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = asn1_cms.Integer


class BodyPartReference(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        ("bodyPartID", asn1_cms.Integer),
        ("bodyPartPath", BodyPartPath),
    ]


class BodyPartReferences(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = BodyPartReference


class CMCUnsignedData(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("bodyPartPath", BodyPartPath),
        ("identifier", asn1_cms.ObjectIdentifier),
        ("content", asn1_cms.Any),
    ]


class OtherStatusInfo(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        ("failInfo", CMCFailInfo),
        ("pendInfo", PendInfo),
        ("extendedFailInfo", ExtendedFailInfo),
    ]


class CMCStatusInfoV2(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("cMCStatus", CMCStatus),
        ("bodyList", BodyPartReferences),
        ("statusString", asn1_cms.UTF8String, {"optional": True}),
        ("otherInfo", OtherStatusInfo, {"optional": True}),
    ]


class OtherInfo(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        ("failInfo", CMCFailInfo),
        ("pendInfo", PendInfo),
    ]


class CMCStatusInfo(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("cMCStatus", CMCStatus),
        ("bodyList", BodyPartList),
        ("statusString", asn1_cms.UTF8String, {"optional": True}),
        ("otherInfo", OtherInfo, {"optional": True}),
    ]


class IdentityProofV2(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("hashAlgID", asn1_algos.AlgorithmIdentifier),
        ("macAlgID", asn1_algos.AlgorithmIdentifier),
        ("witness", asn1_cms.OctetString),
    ]


class PopLinkWitnessV2(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("keyGenAlgorithm", asn1_algos.AlgorithmIdentifier),
        ("macAlgorithm", asn1_algos.AlgorithmIdentifier),
        ("witness", asn1_cms.OctetString),
    ]


class AddExtensions(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("pkiDataReference", asn1_cms.Integer),
        ("certReferences", BodyPartList),
        ("extensions", asn1_x509.Extensions),
    ]


class LraPOPWitness(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("pkiDataBodyid", asn1_cms.Integer),
        ("bodyIds", BodyPartList),
    ]


class OtherMsg(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("bodyPartID", asn1_cms.Integer),
        ("otherMsgType", asn1_cms.ObjectIdentifier),
        ("otherMsgValue", asn1_cms.Any),
    ]


class OtherMsgs(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = OtherMsg


class ORM(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("bodyPartID", asn1_cms.Integer),
        ("requestMessageType", asn1_cms.ObjectIdentifier),
        ("requestMessageValue", asn1_cms.Any),
    ]


class TaggedCertificationRequest(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("bodyPartID", asn1_cms.Integer),
        ("certificationRequest", asn1_csr.CertificationRequest),
    ]


class OptionalValidity(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("notBefore", asn1_x509.Time, {"optional": True}),
        ("notBefore", asn1_x509.Time, {"optional": True}),  # at least one must be presen
    ]


class CertTemplate(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("version", asn1_x509.Version, {"implicit": 0, "optional": True}),
        ("serialNumber", asn1_cms.Integer, {"implicit": 1, "optional": True}),
        ("signingAlg", asn1_algos.AlgorithmIdentifier, {"implicit": 2, "optional": True}),
        ("issuer", asn1_cms.Name, {"explicit": 3, "optional": True}),
        ("validity", OptionalValidity, {"implicit": 4, "optional": True}),
        ("subject", asn1_cms.Name, {"explicit": 5, "optional": True}),
        ("publicKey", asn1_keys.PublicKeyInfo, {"implicit": 6, "optional": True}),
        ("issuerUID", asn1_cms.BitString, {"implicit": 7, "optional": True}),
        ("subjectUID", asn1_cms.BitString, {"implicit": 8, "optional": True}),
        ("extensions", asn1_x509.Extensions, {"implicit": 9, "optional": True}),
    ]


class ControlList(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("bodyList", BodyPartReference),
    ]


class ExtensionReq(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = asn1_x509.Extension


class AttributeTypeAndValue(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("type", asn1_cms.ObjectIdentifier),
        ("value", asn1_cms.Any),
    ]


class AttributeTypeAndValues(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = AttributeTypeAndValue


class CertRequest(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("certReqId", asn1_cms.Integer),
        ("certTemplate", CertTemplate),
        ("controls", AttributeTypeAndValues, {"optional": True}),
    ]


class CertReqMsg(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("certReq", CertRequest),
        ("popo", ProofOfPossession, {"optional": True}),
        ("regInfo", AttributeTypeAndValues, {"optional": True}),
    ]


class TaggedRequest(asn1_cms.Choice):  # type: ignore
    _alternatives = [
        ("tcr", TaggedCertificationRequest, {"implicit": 0}),
        ("crm", CertReqMsg, {"implicit": 1}),
        ("orm", ORM, {"implicit": 2}),
    ]


class ModCertTemplate(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("pkiDataReference", BodyPartPath),
        ("certReferences", BodyPartList),
        ("replace", asn1_x509.Boolean, {"default": True}),
        ("certTemplate", CertTemplate),
    ]


class TaggedRequests(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = TaggedRequest


class EncryptedPOP(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("request", TaggedRequest),
        ("cms", asn1_cms.EncapsulatedContentInfo),
        ("thePOPAlgID", asn1_algos.AlgorithmIdentifier),
        ("witnessAlgID", asn1_algos.AlgorithmIdentifier),
        ("witness", asn1_cms.OctetString),
    ]


class DecryptedPOP(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("bodyPartID", asn1_cms.Integer),
        ("thePOPAlgID", asn1_algos.AlgorithmIdentifier),
        ("thePOP", asn1_cms.OctetString),
    ]


class TaggedAttributeType(asn1_cms.ObjectIdentifier):  # type: ignore
    _map = {
        "1.3.6.1.5.5.7.7.1": "id-cmc-statusInfo",
        "1.3.6.1.5.5.7.7.2": "id-cmc-identification",
        "1.3.6.1.5.5.7.7.3": "id-cmc-identityProof",
        "1.3.6.1.5.5.7.7.4": "id-cmc-dataReturn",
        "1.3.6.1.5.5.7.7.5": "id-cmc-transactionId",
        "1.3.6.1.5.5.7.7.6": "id-cmc-senderNonce",
        "1.3.6.1.5.5.7.7.7": "id-cmc-recipientNonce",
        "1.3.6.1.5.5.7.7.8": "id-cmc-addExtensions",
        "1.3.6.1.5.5.7.7.9": "id-cmc-encryptedPOP",
        "1.3.6.1.5.5.7.7.10": "id-cmc-decryptedPOP",
        "1.3.6.1.5.5.7.7.11": "id-cmc-lraPOPWitness",
        "1.3.6.1.5.5.7.7.15": "id-cmc-getCert",
        "1.3.6.1.5.5.7.7.16": "id-cmc-getCRL",
        "1.3.6.1.5.5.7.7.17": "id-cmc-revokeRequest",
        "1.3.6.1.5.5.7.7.18": "id-cmc-regInfo",
        "1.3.6.1.5.5.7.7.19": "id-cmc-responseInfo",
        "1.3.6.1.5.5.7.7.21": "id-cmc-queryPending",
        "1.3.6.1.5.5.7.7.22": "id-cmc-popLinkRandom",
        "1.3.6.1.5.5.7.7.23": "id-cmc-popLinkWitness",
        "1.3.6.1.5.5.7.7.33": "id-cmc-popLinkWitnessV2",
        "1.3.6.1.5.5.7.7.24": "id-cmc-confirmCertAcceptance",
        "1.3.6.1.5.5.7.7.25": "id-cmc-statusInfoV2",
        "1.3.6.1.5.5.7.7.26": "id-cmc-trustedAnchors",
        "1.3.6.1.5.5.7.7.27": "id-cmc-authData",
        "1.3.6.1.5.5.7.7.28": "id-cmc-batchRequests",
        "1.3.6.1.5.5.7.7.29": "id-cmc-batchResponses",
        "1.3.6.1.5.5.7.7.30": "id-cmc-publishCert",
        "1.3.6.1.5.5.7.7.31": "id-cmc-modCertTemplate",
        "1.3.6.1.5.5.7.7.32": "id-cmc-controlProcessed",
        "1.3.6.1.5.5.7.7.34": "id-cmc-identityProofV2",
    }


class SetOfCMCStatusInfo(asn1_cms.SetOf):  # type: ignore
    _child_spec = CMCStatusInfo


class SetOfUTF8String(asn1_cms.SetOf):  # type: ignore
    _child_spec = asn1_cms.UTF8String


class SetOfInteger(asn1_cms.SetOf):  # type: ignore
    _child_spec = asn1_cms.Integer


class SetOfAddExtensions(asn1_cms.SetOf):  # type: ignore
    _child_spec = AddExtensions


class SetOfEncryptedPOP(asn1_cms.SetOf):  # type: ignore
    _child_spec = EncryptedPOP


class SetOfDecryptedPOP(asn1_cms.SetOf):  # type: ignore
    _child_spec = DecryptedPOP


class SetOfLraPOPWitness(asn1_cms.SetOf):  # type: ignore
    _child_spec = LraPOPWitness


class SetOfGetCert(asn1_cms.SetOf):  # type: ignore
    _child_spec = GetCert


class SetOfGetCRL(asn1_cms.SetOf):  # type: ignore
    _child_spec = GetCRL


class SetOfRevokeRequest(asn1_cms.SetOf):  # type: ignore
    _child_spec = RevokeRequest


class SetOfCMCCertId(asn1_cms.SetOf):  # type: ignore
    _child_spec = asn1_cms.IssuerAndSerialNumber


class SetOfCMCStatusInfoV2(asn1_cms.SetOf):  # type: ignore
    _child_spec = CMCStatusInfoV2


class SetOfPublishTrustAnchors(asn1_cms.SetOf):  # type: ignore
    _child_spec = PublishTrustAnchors


class SetOfAuthPublish(asn1_cms.SetOf):  # type: ignore
    _child_spec = asn1_cms.Integer


class SetOfBodyPartList(asn1_cms.SetOf):  # type: ignore
    _child_spec = BodyPartList


class SetOfCMCPublicationInfo(asn1_cms.SetOf):  # type: ignore
    _child_spec = CMCPublicationInfo


class SetOfModCertTemplate(asn1_cms.SetOf):  # type: ignore
    _child_spec = ModCertTemplate


class SetOfControlsProcessed(asn1_cms.SetOf):  # type: ignore
    _child_spec = BodyPartReferences


class SetOfIdentityProofV2(asn1_cms.SetOf):  # type: ignore
    _child_spec = IdentityProofV2


class TaggedAttribute(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("bodyPartID", asn1_cms.Integer),
        ("attrType", TaggedAttributeType),
        ("attrValues", asn1_cms.Any),
    ]

    _oid_pair = ("attrType", "attrValues")
    _oid_specs = {
        "id-cmc-statusInfo": SetOfCMCStatusInfo,
        "id-cmc-identification": SetOfUTF8String,
        "id-cmc-identityProof": asn1_cms.SetOfOctetString,
        "id-cmc-dataReturn": asn1_cms.SetOfOctetString,
        "id-cmc-transactionId": SetOfInteger,
        "id-cmc-senderNonce": asn1_cms.SetOfOctetString,
        "id-cmc-recipientNonce": asn1_cms.SetOfOctetString,
        "id-cmc-addExtensions": SetOfAddExtensions,
        "id-cmc-encryptedPOP": SetOfEncryptedPOP,
        "id-cmc-decryptedPOP": SetOfDecryptedPOP,
        "id-cmc-lraPOPWitness": SetOfLraPOPWitness,
        "id-cmc-getCert": SetOfGetCert,
        "id-cmc-getCRL": SetOfGetCRL,
        "id-cmc-revokeRequest": SetOfRevokeRequest,
        "id-cmc-regInfo": asn1_cms.SetOfOctetString,
        "id-cmc-responseInfo": asn1_cms.SetOfOctetString,
        "id-cmc-queryPending": asn1_cms.SetOfOctetString,
        "id-cmc-popLinkRandom": asn1_cms.SetOfOctetString,
        "id-cmc-popLinkWitness": asn1_cms.SetOfOctetString,
        "id-cmc-popLinkWitnessV2": asn1_cms.SetOfOctetString,
        "id-cmc-confirmCertAcceptance": SetOfCMCCertId,
        "id-cmc-statusInfoV2": SetOfCMCStatusInfoV2,
        "id-cmc-trustedAnchors": SetOfPublishTrustAnchors,
        "id-cmc-authData": SetOfAuthPublish,
        "id-cmc-batchRequests": SetOfBodyPartList,
        "id-cmc-batchResponses": SetOfBodyPartList,
        "id-cmc-publishCert": SetOfCMCPublicationInfo,
        "id-cmc-modCertTemplate": SetOfModCertTemplate,
        "id-cmc-controlProcessed": SetOfControlsProcessed,
        "id-cmc-identityProofV2": SetOfIdentityProofV2,
    }


class Controls(asn1_cms.SequenceOf):  # type: ignore
    _child_spec = TaggedAttribute


class PKIData(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("controlSequence", Controls),
        ("reqSequence", TaggedRequests),
        ("cmsSequence", TaggedContentInfos),
        ("otherMsgSequence", OtherMsgs),
    ]


class PKIResponse(asn1_cms.Sequence):  # type: ignore
    _fields = [
        ("controlSequence", Controls),
        ("cmsSequence", TaggedContentInfos),
        ("otherMsgSequence", OtherMsgs),
    ]
