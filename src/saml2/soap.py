#!/usr/bin/env python
#

"""
Suppport for the client part of the SAML2.0 SOAP binding.
"""
import logging
import re
from xml.etree import ElementTree as ElementTree

try:
    import defusedxml.lxml as defused_etree
except:
    import defusedxml.ElementTree as defused_etree


from saml2 import create_class_from_element_tree
from saml2.samlp import NAMESPACE as SAMLP_NAMESPACE
from saml2.schema import soapenv


logger = logging.getLogger(__name__)


class XmlParseError(Exception):
    pass


class WrongMessageType(Exception):
    pass


def parse_soap_enveloped_saml_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE, "{%s}LogoutResponse" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_logout_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE, "{%s}LogoutResponse" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_attribute_query(text):
    expected_tag = "{%s}AttributeQuery" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_attribute_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE, "{%s}AttributeResponse" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_logout_request(text):
    expected_tag = "{%s}LogoutRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_authn_request(text):
    expected_tag = "{%s}AuthnRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_artifact_resolve(text):
    expected_tag = "{%s}ArtifactResolve" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_artifact_response(text):
    expected_tag = "{%s}ArtifactResponse" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_name_id_mapping_request(text):
    expected_tag = "{%s}NameIDMappingRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_name_id_mapping_response(text):
    expected_tag = "{%s}NameIDMappingResponse" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_manage_name_id_request(text):
    expected_tag = "{%s}ManageNameIDRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_manage_name_id_response(text):
    expected_tag = "{%s}ManageNameIDResponse" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_assertion_id_request(text):
    expected_tag = "{%s}AssertionIDRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_assertion_id_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE, "{%s}AssertionIDResponse" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_authn_query(text):
    expected_tag = "{%s}AuthnQuery" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_authn_query_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_authn_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


# def parse_soap_enveloped_saml_logout_response(text):
#    expected_tag = '{%s}LogoutResponse' % SAMLP_NAMESPACE
#    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def _extract_body_header_from_soap(text):
    """Parses a SOAP message and returns the
    body and headers as a dictionary.

    :param text: The SOAP object as XML
    :return: The body and headers as elementtree instances
    """
    try:
        envelope = defused_etree.fromstring(text)
    except Exception as exc:
        raise XmlParseError(f"{exc}")

    envelope_tag = "{%s}Envelope" % soapenv.NAMESPACE
    if envelope.tag != envelope_tag:
        raise ValueError(f"Invalid envelope tag '{envelope.tag}' should be '{envelope_tag}'")

    if len(envelope) < 1:
        raise Exception("No items in envelope.")

    env = {"header": [], "body": None}

    for part in envelope:
        if part.tag == "{%s}Body" % soapenv.NAMESPACE:
            if len(part) < 1:
                raise Exception("No items in envelope body.")
            env["body"] = part
        elif part.tag == "{%s}Header" % soapenv.NAMESPACE:
            for item in part:
                env["header"].append(item)

    return env


def parse_soap_enveloped_saml_thingy(text, expected_tags):
    """Parses a SOAP enveloped SAML thing and returns the thing as
    a string.

    :param text: The SOAP object as XML string
    :param expected_tags: What the tag of the SAML thingy is expected to be.
    :return: SAML thingy as a string
    """
    env = _extract_body_header_from_soap(text)
    body = env["body"]

    if len(body) != 1:
        raise Exception(f"Expected a single child element, found {n_children}")

    if body is None:
        return ""

    saml_part = body[0]
    if saml_part.tag in expected_tags:
        return defused_etree.tostring(saml_part, encoding="UTF-8")
    else:
        raise WrongMessageType(f"Was '{saml_part.tag}' expected one of {expected_tags}")


NS_AND_TAG = re.compile(r"\{([^}]+)\}(.*)")


def instanciate_class(item, modules):
    m = NS_AND_TAG.match(item.tag)
    ns, tag = m.groups()
    for module in modules:
        if module.NAMESPACE == ns:
            try:
                target = module.ELEMENT_BY_TAG[tag]
                return create_class_from_element_tree(target, item)
            except KeyError:
                continue
    raise Exception(f"Unknown class: ns='{ns}', tag='{tag}'")


def class_instances_from_soap_enveloped_saml_thingies(text, modules):
    """Parses a SOAP enveloped header and body SAML thing and returns the
    thing as a dictionary class instance.

    :param text: The SOAP object as XML
    :param modules: modules representing xsd schemas
    :return: The body and headers as class instances
    """
    env = _extract_body_header_from_soap(text)

    # broken envelope check was here
    env["body"] = instanciate_class(env["body"][0], modules)
    env["header"] = [instanciate_class(x, modules) for x in env["header"]]

    return env


def open_soap_envelope(text):
    """

    :param text: SOAP message
    :return: dictionary with two keys "body"/"header"
    """
    env = _extract_body_header_from_soap(text)

    # broken envelope check was here
    env["body"] = defused_etree.tostring(env["body"][0], encoding="UTF-8")
    env["header"] = [defused_etree.tostring(x, encoding="UTF-8") for x in env["header"]]

    return env


def make_soap_enveloped_saml_thingy(thingy, headers=None):
    """Returns a soap envelope containing a SAML request
    as a text string.

    :param thingy: The SAML thingy
    :return: The SOAP envelope as a string
    """
    soap_envelope = soapenv.Envelope()

    if headers:
        _header = soapenv.Header()
        _header.add_extension_elements(headers)
        soap_envelope.header = _header

    soap_envelope.body = soapenv.Body()
    soap_envelope.body.add_extension_element(thingy)

    return f"{soap_envelope}"


def soap_fault(message=None, actor=None, code=None, detail=None):
    """Create a SOAP Fault message

    :param message: Human readable error message
    :param actor: Who discovered the error
    :param code: Error code
    :param detail: More specific error message
    :return: A SOAP Fault message as a string
    """
    _string = _actor = _code = _detail = None

    if message:
        _string = soapenv.Fault_faultstring(text=message)
    if actor:
        _actor = soapenv.Fault_faultactor(text=actor)
    if code:
        _code = soapenv.Fault_faultcode(text=code)
    if detail:
        _detail = soapenv.Fault_detail(text=detail)

    fault = soapenv.Fault(
        faultcode=_code,
        faultstring=_string,
        faultactor=_actor,
        detail=_detail,
    )

    return f"{fault}"
