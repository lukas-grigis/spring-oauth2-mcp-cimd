-- Two databases on the shared Postgres:
--   keycloak   — Keycloak's realm store (so the master-realm sslRequired override survives a restart)
--   authserver — the Spring Authorization Server OAuth2 stores (registered clients, authorizations, consents)
CREATE
DATABASE keycloak;
CREATE
DATABASE authserver;
