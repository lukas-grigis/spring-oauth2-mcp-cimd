# Standards and sources

Plain-English reference for the OAuth2 / OIDC / MCP standards this project builds on, with a link to
every primary source. If a claim in the README or in this code needs backing, it is cited here.
Nothing below is from memory; each line links to the spec it paraphrases.

## What changed: MCP client registration (2025-11-25)

The MCP authorization spec was revised on 2025-11-25. It changed how an MCP client obtains an OAuth
client identity:

- **Client ID Metadata Documents (CIMD)** became the preferred mechanism. Verbatim: _"Authorization
  servers and MCP clients **SHOULD** support OAuth Client ID Metadata Documents."_
- **Dynamic Client Registration (DCR, RFC 7591)** was demoted. Verbatim: _"MCP clients and
  authorization servers **MAY** support the OAuth 2.0 Dynamic Client Registration Protocol [RFC7591]
  ... This option is included for backwards compatibility with earlier versions of the MCP
  authorization spec."_

The earlier 2025-06-18 revision had DCR at SHOULD; 2025-11-25 dropped it to MAY and put CIMD above
it. Discovery (RFC 9728 / RFC 8414) and audience binding (RFC 8707) stayed at MUST.

Source: [MCP authorization specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

**This project implements CIMD:** its authorization server resolves an MCP client from the metadata
document behind its URL `client_id` and exposes no registration endpoint. It does not implement DCR —
that pattern lives in the companion repo,
[`spring-oauth2-mcp`](https://github.com/lukas-grigis/spring-oauth2-mcp).

## DCR vs CIMD, in plain English

**DCR (RFC 7591)** — the client _registers_. It POSTs its metadata to a registration endpoint and
gets back a `client_id`; the server stores a record. Analogy: fill out a form at the front desk to
get a badge.

**CIMD (IETF draft)** — the client's `client_id` _is a URL_. The authorization server _fetches_ that
URL to read the client's metadata. No registration step, no stored record. Analogy: your business
card has a web address, and the guard looks you up by visiting it.

Two things worth knowing about CIMD:

- It is an **IETF draft, not a finished RFC.** The MCP 2025-11-25 spec references
  [
  `draft-ietf-oauth-client-id-metadata-document-00`](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/);
  the working-group draft has since advanced to `-02` (2026-07-06) and is still active. Moving target.
- It carries its own risk: an authorization server fetching a **client-controlled URL** is an SSRF
  vector (the server can be steered at internal endpoints), and pinning trust to localhost redirect
  URIs invites localhost impersonation. The MCP spec calls this out in its CIMD security section.

## The RFCs, by job

| RFC                                                | What it does                                                                                            |
|----------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) | OAuth 2.0 itself: the framework everything else builds on (Oct 2012).                                   |
| [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) | Dynamic Client Registration: "register me, give me a `client_id`" (Jul 2015).                           |
| [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592) | DCR _Management_: read / update / delete an **already-registered** client. Not create (Jul 2015).       |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Authorization Server Metadata: the AS's `/.well-known/oauth-authorization-server` (Jun 2018).           |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | Resource Indicators: the `resource` parameter that binds a token to one API via `aud` (Feb 2020).       |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) | OAuth 2.0 Security Best Current Practice: the "do these to not get hacked" rulebook (Jan 2025).         |
| [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) | Protected Resource Metadata: how a `401` tells the client where the authorization server is (Apr 2025). |

A common mix-up worth getting right: to gate **who may register**, you use RFC 7591's _initial
access token_. RFC 7592 only governs read/update/delete of a client that already exists. Different
RFCs, different jobs.

## How this demo maps to each spec

| Spec                | Where in the code                                                                                                                                                  |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| RFC 7591 (DCR)      | **not implemented** — `dynamicClientRegistration(false)` in `WebSecurityConfiguration`; no registration endpoint is exposed (the companion repo is the DCR reference). |
| RFC 9728 (PRM)      | the MCP server's `401` + `WWW-Authenticate` pointing at `/.well-known/oauth-protected-resource/mcp` (`mcpServerOAuth2`).                                           |
| RFC 8414 (AS meta)  | the authorization server's `/.well-known/oauth-authorization-server` — with `client_id_metadata_document_supported: true` and no `registration_endpoint`.          |
| RFC 8707 (resource) | `bindAudience` in `AccessTokenClaimsConfiguration` stamps `aud`; `validateAudienceClaim` on the resource server rejects a token whose `aud` is for something else. |
| RFC 9700 (sec BCP)  | `reuseRefreshTokens(false)` (§2.2.2 requires rotation for public clients), PKCE, exact redirect-URI matching.                                                      |
| RFC 6749 (OAuth2)   | the whole authorization-code flow; §4.4 (client_credentials) is why refresh tokens are stamped only for `authorization_code`.                                      |
| CIMD                | `cimd(true)` in `WebSecurityConfiguration`; the fetch + validate + cache path (`ClientIdMetadataDocumentRegisteredClientRepository`) wired in `OAuth2StoreConfiguration`; the SSRF guard in `SsrfGuardConfiguration`. |

## Questions you will get asked

**"Isn't CIMD just an IETF draft? Why build on it?"**
It is a draft, and a moving target (see above). But the MCP 2025-11-25 spec makes it the SHOULD for
authorization servers and clients, and live CIMD clients exist — Claude Code publishes its identity
document at `https://claude.ai/oauth/claude-code-client-metadata`. This repo shows that SHOULD path;
the companion repo covers the DCR bridge for clients that haven't moved yet.

**"The server fetches a client-controlled URL — what about SSRF?"**
That is CIMD's headline risk, and the reason this repo has exactly one guard bean: an
`InetAddressFilter` enforced at DNS-resolution time inside the metadata fetcher's HTTP client, refusing
private, link-local and loopback ranges (the demo profile relaxes loopback only, so the locally served
document is fetchable). See `SsrfGuardConfiguration`.

**"Anyone with a URL can be a client — isn't that open registration by another name?"**
The exposure is similar to open DCR, with two differences: nothing accumulates server-side (documents
are resolved and briefly cached, never stored), and the identity is self-verifying (the document's
`client_id` must equal the URL it was fetched from). PKCE and exact redirect-URI matching still guard
the flow. What this demo deliberately omits is a trust policy for *which* URLs to accept.

**"Is this production-ready?"**
No, and the README says so. It is a reference. Beyond the demo shortcuts (plain-HTTP loopback client
IDs, relaxed SSRF guard), the first real-world addition is per-client consent at the authorization
server: with one shared upstream Keycloak client, every CIMD client rides the same federated consent —
the confused-deputy problem applies to CIMD exactly as it did to DCR.

**"Why is it on Keycloak?"**
Keycloak stands in for an enterprise IdP that knows nothing about CIMD — it only authenticates the
human. The CIMD resolution happens in the Spring Authorization Server in front of it, which is the
point: the IdP is a configuration choice, and none of the client-identity machinery touches it.

## All sources

- [MCP authorization specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OAuth Client ID Metadata Document (CIMD), IETF draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol](https://www.rfc-editor.org/rfc/rfc7591)
- [RFC 7592 — OAuth 2.0 Dynamic Client Registration Management Protocol](https://www.rfc-editor.org/rfc/rfc7592)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
