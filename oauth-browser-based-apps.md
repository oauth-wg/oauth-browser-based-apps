---
title: OAuth 2.0 for Browser-Based Apps
docname: draft-parecki-oauth-browser-based-apps-02
date: 2018-11-19

ipr: trust200902
area: OAuth
kw: Internet-Draft
cat: bcp

coding: us-ascii
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
  -
    ins: A. Parecki
    name: Aaron Parecki
    org: Okta
    email: aaron@parecki.com
    uri: https://aaronparecki.com
  -
    ins: D. Waite
    name: David Waite
    org: Ping Identity
    email: david@alkaline-solutions.com

normative:
  RFC2119:
  RFC6749:
  RFC6819:
  RFC7636:
  RFC8252:
  CSP2:
    title: Content Security Policy
    author:
    - name: Mike West
      ins: M. West
      org: Google, Inc
    - name: Adam Barth
      ins: A. Barth
      org: Google, Inc
    - name: Dan Veditz
      ins: D. Veditz
      org: Mozilla Corporation
    date: December 2016
  Fetch:
    title: Fetch
    author:
      name: whatwg
      ins: whatwg
    date: 2018
  oauth-security-topics:
    title: OAuth 2.0 Security Best Current Practice
    author:
    - name: Torsten Lodderstedt
      ins: T. Lodderstedt
      org: yes.com
    - name: John Bradley
      ins: J. Bradley
      org: Yubico
    - name: Andrey Labunets
      ins: A. Labunets
      org: Facebook
    - name: Daniel Fett
      ins: D. Fett
      org: yes.com
    date: November 2018

informative:
  HTML:
    title: HTML
    author:
      name: whatwg
      ins: whatwg
    date: 2018

--- abstract

OAuth 2.0 authorization requests from apps running entirely in a browser are unable
to use a Client Secret during the process, since they have no way to keep a secret
confidential. This specification details the security considerations that must be
taken into account when developing browser-based applications, as well as best
practices for how they can securely implement OAuth 2.0.

--- middle

Introduction {#introduction}
============

This specification describes the current best practices for implementing OAuth 2.0
authorization flows in applications running entirely in a browser.

For native application developers using OAuth 2.0 and OpenID Connect, an IETF BCP
(best current practice) was published that guides integration of these technologies.
This document is formally known as {{RFC8252}} or BCP 212, but nicknamed "AppAuth" after
the OpenID Foundation-sponsored set of libraries that assist developers in adopting
these practices.

AppAuth steers developers away from performing user authorization via embedding user
agents such as browser controls into native apps, instead insisting that an external
agent (such as the system browser) be used. The RFC continues on to promote
capabilities and supplemental specifications beyond the base OAuth 2.0 and
OpenID Connect specifications to improve baseline security, such as {{RFC7636}},
also known as PKCE.

This specification addresses the similarities between implementing OAuth for native
apps as well as browser-based apps, and includes additional considerations when
running in a browser. This is primarily focused on OAuth, except where OpenID Connect
provides additional considerations.


Notational Conventions
======================

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}.


Terminology
===========

In addition to the terms defined in referenced specifications, this document uses
the following terms:

"OAuth":
: In this document, "OAuth" refers to OAuth 2.0, {{RFC6749}}.

"Browser-based application":
: An application that runs entirely in a web browser, usually written in
  JavaScript, where the source code is downloaded from a domain prior to execution.
  Also sometimes referred to as a "single-page application", or "SPA".


Overview
========

For authorizing users within a browser-based application, the best current practice is to

* Use the OAuth 2.0 authorization code flow with the PKCE extension
* Require the OAuth 2.0 state parameter
* Recommend exact matching of redirect URIs, and require the hostname of the redirect URI match the hostname of the URL the app was served from
* Do not return access tokens in the front channel

Previously it was recommended that browser-based applications use the OAuth 2.0 Implicit
flow. That approach has several drawbacks, including the fact that access tokens are
returned in the front-channel via the fragment part of the redirect URI, and as such
are vulnerable to a variety of attacks where the access token can be intercepted or
stolen. See {{implicit_flow}} for a deeper analysis of these attacks and the drawbacks
of using the Implicit flow in browsers, many of which are described by {{oauth-security-topics}}.

Instead, browser-based apps can perform the OAuth 2.0 authorization code flow
and make a POST request to the token endpoint to exchange an authorization code
for an access token, just like other OAuth clients. This ensures that access tokens
are not sent via the less secure front-channel, and are only returned over an HTTPS
connection initiated from the application. Combined with PKCE, this enables the
authorization server to ensure that authorization codes are useless even if
intercepted in transport.


First-Party Applications
========================

While OAuth and OpenID Connect were initially created to allow third-party
applications to access an API on behalf of a user, they have both proven to be
useful in a first-party scenario as well. First-party apps are applications created
by the same organization that provides the API being accessed by the application.

For example, a web email client provided by the operator of the email account,
or a mobile banking application created by bank itself. (Note that there is no
requirement that the application actually be developed by the same company; a mobile
banking application developed by a contractor that is branded as the bank's
application is still considered a first-party application.) The first-party app
consideration is about the user's relationship to the application and the service.

To conform to this best practice, first-party applications using OAuth or OpenID
Connect MUST use an OAuth Authorization Code flow as described later in this
document or use the OAuth Password grant.

It is strongly RECOMMENDED that applications use the Authorization Code flow over
the Password grant for several reasons. By redirecting to the authorization server,
this provides the authorization server the opportunity to prompt the user for
multi-factor authentication options, take advantage of single-sign-on sessions,
or use third-party identity providers. In contrast, the Password grant does not
provide any built-in mechanism for these, and must be extended with custom code.


Architectural Considerations
============================

In some cases, it may make sense to avoid the use of a strictly browser-based OAuth
application entirely, instead using an architecture that can provide better security.


Apps Served from the Same Domain as the API
-------------------------------------------

For simple system architectures, such as when the JavaScript application is served
from the same domain as the API (resource server) being accessed, it is likely a
better decision to avoid using OAuth entirely, and just use session authentication
to communicate with the API.

OAuth and OpenID Connect provide very little benefit in this deployment scenario,
so it is recommended to reconsider whether you need OAuth or OpenID Connect at all
in this case. Session authentication has the benefit of having fewer moving parts
and fewer attack vectors. OAuth and OpenID Connect were created primarily for
third-party or federated access to APIs, so may not be the best solution in a
same-domain scenario.

JavaScript App with a Backend Component
---------------------------------------

Implementations MAY consider moving the authorization code exchange and handling of
access and refresh tokens to a backend component in order to avoid the risks inherent
in handling access tokens from a purely browser based app. In this case, the backend
component can be a confidential client and can be secured accordingly.

Security of the connection between code running in the browser and this backend
component is assumed to utilize browser-level protection mechanisms. Details are out
of scope of this document.


Authorization Code Flow {#authorization_code_flow}
=======================

Public browser-based apps needing user authorization create an authorization
request URI with the authorization code grant type per Section 4.1 of
OAuth 2.0 {{RFC6749}}, using a redirect URI capable of being received by the app.


Initiating the Authorization Request from a Browser-Based Application {#auth_code_request}
---------------------------------------------------------------------

Public browser-based apps MUST implement the Proof Key for Code Exchange
(PKCE {{RFC7636}}) extension to OAuth, and authorization servers MUST support
PKCE for such clients.

The PKCE extension prevents an attack where the authorization code is intercepted
and exchanged for an access token by a malicious client, by providing the
authorization server with a way to verify the same client instance that exchanges
the authorization code is the same one that initiated the flow.

Browser-based apps MUST use the OAuth 2.0 "state" parameter to protect themselves
against Cross-Site Request Forgery and authorization code swap attacks and MUST use
a unique value for each authorization request, and MUST verify the returned state
in the authorization response matches the original state the app created.


Handling the Authorization Code Redirect {#auth_code_redirect}
----------------------------------------

Authorization servers SHOULD require an exact match of a registered redirect URI.

If an authorization server wishes to provide some flexibility in redirect URI usage
to clients, it MAY require that only the hostname component of the redirect URI match
the hostname of the URL the application is served from.

Authorization servers MUST support one of the two redirect URI validation mechanisms
as described above.


Security Considerations
=======================


Registration of Browser-Based Apps   {#client_registration}
----------------------------------

Browser-based applications are considered public clients as defined by section 2.1
of OAuth 2.0 {{RFC6749}}, and MUST be registered with the authorization server as
such. Authorization servers MUST record the client type in the client registration
details in order to identify and process requests accordingly.

Authorization servers MUST require that browser-based applications register
one or more redirect URIs.


Client Authentication   {#client_authentication}
---------------------

Since a browser-based application's source code is delivered to the end-user's
browser, it cannot contain provisioned secrets. As such, a browser-based app
with native OAuth support is considered a public client as defined by Section 2.1
of OAuth 2.0 {{RFC6749}}.

Secrets that are statically included as part of an app distributed to
multiple users should not be treated as confidential secrets, as one
user may inspect their copy and learn the shared secret.  For this
reason, and those stated in Section 5.3.1 of {{RFC6819}}, it is NOT RECOMMENDED
for authorization servers to require client authentication of browser-based
applications using a shared secret, as this serves little value beyond
client identification which is already provided by the client_id request parameter.

Authorization servers that still require a statically included shared
secret for SPA clients MUST treat the client as a public
client, and not accept the secret as proof of the client's identity. Without
additional measures, such clients are subject to client impersonation
(see {{client_impersonation}} below).


Client Impersonation   {#client_impersonation}
--------------------

As stated in Section 10.2 of OAuth 2.0 {{RFC6749}}, the authorization
server SHOULD NOT process authorization requests automatically
without user consent or interaction, except when the identity of the
client can be assured. Even when the user has previously approved an
authorization request for a given client_id, the request SHOULD be
processed as if no previous request had been approved, unless the identity of
the client can be proven.

If authorization servers restrict redirect URIs to a fixed set of absolute
HTTPS URIs without wildcard domains, paths, or query string components, this exact
match of registered absolute HTTPS URIs MAY be accepted by authorization servers as
proof of identity of the client for the purpose of deciding whether to automatically
process an authorization request when a previous request for the client_id
has already been approved.


Cross-Site Request Forgery Protections   {#csrf_protection}
--------------------------------------

Section 5.3.5 of {{RFC6819}} recommends using the "state" parameter to
link client requests and responses to prevent CSRF (Cross-Site Request Forgery)
attacks. To conform to this best practice, use of the "state" parameter is
REQUIRED, as described in {{auth_code_request}}.


Authorization Server Mix-Up Mitigation   {#auth_server_mixup}
--------------------------------------

The security considerations around the authorization server mix-up that
are referenced in Section 8.10 of {{RFC8252}} also apply to browser-based apps.

Clients MUST use a unique redirect URI for each authorization server used by the
application. The client MUST store the redirect URI along with the session data
(e.g. along with "state") and MUST verify that the URI on which the authorization
response was received exactly matches.


Cross-Domain Requests  {#cors}
---------------------

To complete the authorization code flow, the browser-based application will
need to exchange the authorization code for an access token at the token endpoint.
If the authorization server provides additional endpoints to the application, such
as metadata URLs, dynamic client registration, revocation, introspection, discovery or
user info endpoints, these endpoints may also be accessed by the browser-based app.
Since these requests will be made from a browser, authorization servers MUST support
the necessary CORS headers (defined in {{Fetch}}) to allow the browser to make the
request.

This specification does not include guidelines for deciding whether a CORS policy
for the token endpoint should be a wildcard origin or more restrictive. Note,
however, that the browser will attempt to GET or POST to the API endpoint before
knowing any CORS policy; it simply hides the succeeding or failing result from
JavaScript if the policy does not allow sharing. If POSTs in particular from
unsupported single-page applications are to be rejected as errors per authorization
server security policy, such rejection is typically done based on the Origin
request header.


Content-Security Policy   {#csp}
-----------------------

A browser-based application that wishes to use either long-lived refresh tokens or
privileged scopes SHOULD restrict its JavaScript execution to a set of statically
hosted scripts via a Content Security Policy ({{CSP2}}) or similar mechanism. A
strong Content Security Policy can limit the potential attack vectors for malicious
JavaScript to be executed on the page.


OAuth Implicit Grant Authorization Flow   {#implicit_flow}
---------------------------------------

The OAuth 2.0 Implicit grant authorization flow (defined in Section 4.2 of
OAuth 2.0 {{RFC6749}}) works by receiving an access token in the HTTP redirect
(front-channel) immediately without the code exchange step. In this case, the access
token is returned in the fragment part of the redirect URI, providing an attacker
with several opportunities to intercept and steal the access token. Several attacks
on the implicit flow are described by {{RFC6819}} and {{oauth-security-topics}},
not all of which have sufficient mitigation strategies.

### Threat: Interception of the Redirect URI

If an attacker is able to cause the authorization response to be sent to a URI under
his control, he will directly get access to the fragment carrying the access token.
A method of performing this attack is described in detail in {{oauth-security-topics}}.

### Threat: Access Token Leak in Browser History

An attacker could obtain the access token from the browser's history.
The countermeasures recommended by {{RFC6819}} are limited to using short expiration
times for tokens, and indicating that browsers should not cache the response.
Neither of these fully prevent this attack, they only reduce the potential damage.

### Threat: Manipulation of Scripts

An attacker could modify the page or inject scripts into the browser via various
means, including when the browser's HTTPS connection is being man-in-the-middled
by for example a corporate network. While this type of attack is typically out of
scope of basic security recommendations to prevent, in the case of browser-based
apps it is much easier to perform this kind of attack, where an injected script
can suddenly have access to everything on the page.

### Threat: Access Token Leak to Third Party Scripts

It is relatively common to use third-party scripts in browser-based apps, such as
analytics tools, crash reporting, and even things like a Facebook or Twitter "like" button.
In these situations, the author of the application may not be able to be fully aware
of the entirety of the code running in the application. When an access token is
returned in the fragment, it is visible to any third-party scripts on the page.

### Countermeasures

In addition to the countermeasures described by {{RFC6819}} and {{oauth-security-topics}},
using the authorization code with PKCE avoids these attacks.

When PKCE is used, if an authorization code is stolen in transport, the attacker is
unable to do anything with the authorization code.

### Disadvantages of the Implicit Flow

There are several additional reasons the Implicit flow is disadvantageous compared to
using the standard Authorization Code flow.

* OAuth 2.0 provides no mechanism for a client to verify that an access token was
  issued to it, which could lead to misuse and possible impersonation attacks if
  a malicious party hands off an access token it retrieved through some other means
  to the client.
* Supporting the implicit flow requires additional code, more upkeep and
  understanding of the related security considerations, while limiting the
  authorization server to just the authorization code flow reduces the attack surface
  of the implementation.
* If the JavaScript application gets wrapped into a native app, then {{RFC8252}}
  also requires the use of the authorization code flow with PKCE anyway.

In OpenID Connect, the id_token is sent in a known format (as a JWT), and digitally
signed. Performing OpenID Connect using the authorization code flow also provides
the additional benefit of the client not needing to verify the JWT signature, as the
token will have been fetched over an HTTPS connection directly from the authorization
server. However, returning an id_token using the Implicit flow requires the client
validate the JWT signature as malicious parties could otherwise craft and supply
fraudulent id_tokens.

### Historic Note

Historically, the Implicit flow provided an advantage to single-page apps since
JavaScript could always arbitrarily read and manipulate the fragment portion of the
URL without triggering a page reload. Now with the Session History API (described in
"Session history and navigation" of {{HTML}}), browsers have a mechanism to modify
the path component of the URL without triggering a page reload, so this overloaded
use of the fragment portion is no longer needed.


Additional Security Considerations
----------------------------------

The OWASP Foundation (https://www.owasp.org/) maintains a set of security
recommendations and best practices for web applications, and it is RECOMMENDED
to follow these best practices when creating an OAuth 2.0 Browser-Based application.


IANA Considerations   {#iana}
===================

This document does not require any IANA actions.


--- back

Server Support Checklist
====================================

OAuth servers that support browser-based apps MUST:

1.  Require "https" scheme redirect URIs.

2.  Require exact matching on redirect URIs or matching the hostname the application
    is served from.

3.  Support PKCE {{RFC7636}}. Required to protect authorization code
    grants sent to public clients. See {{auth_code_request}}

4.  Support cross-domain requests at the token endpoint in order to allow browsers
    to make the authorization code exchange request. See {{cors}}

5.  Not assume that browser-based clients can keep a secret, and SHOULD NOT issue
    secrets to applications of this type.


Acknowledgements
================

The authors would like to acknowledge the work of William Denniss and John Bradley,
whose recommendation for native apps informed many of the best practices for
browser-based applications. The authors would also like to thank Hannes Tschofenig
and Torsten Lodderstedt, as well as all the attendees of the Internet Identity Workshop 27
session at which this BCP was originally proposed.

The following individuals contributed ideas, feedback, and wording that shaped and
formed the final specification:

Annabelle Backman, Brian Campbell, Brock Allen, Christian Mainka, Daniel Fett,
George Fletcher, Hannes Tschofenig, John Bradley, Joseph Heenan, Justin Richer,
Karl McGuinness, Tomek Stojecki, Torsten Lodderstedt, and Vittorio Bertocci.


--- fluff
