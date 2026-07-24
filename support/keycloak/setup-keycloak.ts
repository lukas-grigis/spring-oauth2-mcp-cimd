/**
 * Idempotent Keycloak provisioner for the spring-oauth2-mcp demo.
 *
 * Converges Keycloak to the desired state in keycloak.config.ts: the `demo` realm, the `user`/`admin`
 * realm roles, the confidential `keycloak` client the authorization server federates through (with the
 * all-important realm-roles → flat `roles` ID-token mapper), and the alice/bob dev users.
 *
 * Re-running is safe: every resource is "create (ignore 409) → find → update", and passwords and role
 * mappings are re-synced on existing users.
 *
 * Usage: npm run setup
 */

import KcAdminClient from "@keycloak/keycloak-admin-client";
import {type ClientConfig, configSchema, type UserConfig} from "./config.js";
import rawConfig from "./keycloak.config.js";

const config = configSchema.parse(rawConfig);

/** True when an admin-client error is a Keycloak "409 Conflict" (resource already exists). */
function isConflict(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as { response?: { status?: number } }).response?.status === 409
  );
}

/** Run `fn`, swallowing a 409 so create steps are idempotent. */
async function createIgnoreConflict(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
    console.log(`   ${label} — created.`);
  } catch (err) {
    if (isConflict(err)) {
      console.log(`   ${label} — exists.`);
      return;
    }
    throw err;
  }
}

async function ensureRealm(kc: KcAdminClient): Promise<void> {
  console.log(`\n1. Realm: ${config.realm}`);
  const realmRep = {
    realm: config.realm,
    enabled: true,
    sslRequired: "none" as const,
    loginWithEmailAllowed: true,
    accessTokenLifespan: 300,
  };
  await createIgnoreConflict(config.realm, () => kc.realms.create(realmRep));
  await kc.realms.update({realm: config.realm}, realmRep);
  kc.setConfig({realmName: config.realm});
}

async function ensureRealmRoles(kc: KcAdminClient): Promise<void> {
  console.log(`\n2. Realm roles: [${config.realmRoles.join(", ")}]`);
  for (const name of config.realmRoles) {
    await createIgnoreConflict(name, () => kc.roles.create({name}));
  }
}

async function ensureClient(kc: KcAdminClient, client: ClientConfig): Promise<void> {
  console.log(`\n3. Client: ${client.clientId} (confidential, authorization_code)`);
  const rep = {
    clientId: client.clientId,
    enabled: true,
    publicClient: false,
    clientAuthenticatorType: "client-secret",
    secret: client.secret,
    standardFlowEnabled: true,
    directAccessGrantsEnabled: false,
    serviceAccountsEnabled: false,
    // Include the user's realm roles in the token. With the secure default (false) and no client role
    // scope-mappings, Keycloak strips ALL realm roles — so the realm-roles mapper below emits nothing
    // and the authorization server maps an empty scope set (deny-all). True for this demo; in production
    // prefer false + explicit client role scope-mappings.
    fullScopeAllowed: true,
    // Show Keycloak's consent screen when the authorization server federates the login — the realistic
    // "grant this connection access to your account" step users see with MCP connectors.
    consentRequired: true,
    redirectUris: client.redirectUris,
    webOrigins: client.webOrigins,
    protocol: "openid-connect" as const,
  };

  await createIgnoreConflict(client.clientId, () => kc.clients.create(rep));
  const found = await kc.clients.find({clientId: client.clientId});
  const uuid = found[0]?.id;
  if (!uuid) {
    throw new Error(`Client "${client.clientId}" not found after create — cannot converge.`);
  }
  await kc.clients.update({id: uuid}, rep);

  await ensureRealmRolesIdTokenMapper(kc, uuid, client.clientId);
}

/**
 * Emit the user's realm roles as a flat `roles` claim in the ID token. Keycloak's default mapper only
 * writes the nested `realm_access.roles` to the ACCESS token — but the authorization server is an OIDC
 * client reading the ID token, so without this it would see no roles, map them to an empty scope set,
 * and (failing closed) deny every tool for both alice and bob. This is the contract between Keycloak and
 * the authorization server's ScopeMappingConfiguration. Idempotent: a re-run 409s and is ignored.
 */
async function ensureRealmRolesIdTokenMapper(kc: KcAdminClient, clientUuid: string, clientId: string): Promise<void> {
  await createIgnoreConflict(`realm-roles → 'roles' id-token mapper on "${clientId}"`, () =>
    kc.clients.addProtocolMapper(
      {id: clientUuid},
      {
        name: "realm roles",
        protocol: "openid-connect",
        protocolMapper: "oidc-usermodel-realm-role-mapper",
        config: {
          "claim.name": "roles",
          "jsonType.label": "String",
          multivalued: "true",
          "id.token.claim": "true",
          "access.token.claim": "true",
          "userinfo.token.claim": "true",
          "introspection.token.claim": "false",
        },
      },
    ),
  );
}

async function ensureUser(kc: KcAdminClient, user: UserConfig): Promise<void> {
  await createIgnoreConflict(`user "${user.username}"`, () =>
    kc.users.create({
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      emailVerified: true,
      enabled: true,
      credentials: [{type: "password", value: user.password, temporary: false}],
    }),
  );

  const found = await kc.users.find({username: user.username, exact: true});
  const id = found[0]?.id;
  if (!id) {
    throw new Error(`User "${user.username}" not found after create — cannot converge.`);
  }

  // Re-sync the password so an existing user converges on re-runs.
  await kc.users.resetPassword({
    id,
    credential: {type: "password", value: user.password, temporary: false},
  });

  // Re-sync realm role mappings (addRealmRoleMappings is additive + Keycloak-idempotent).
  for (const roleName of user.realmRoles) {
    const role = await kc.roles.findOneByName({name: roleName});
    if (!role?.id) {
      throw new Error(`Realm role "${roleName}" for user "${user.username}" does not exist.`);
    }
    await kc.users.addRealmRoleMappings({id, roles: [{id: role.id, name: roleName}]});
  }
  console.log(`   ${user.username} / ${user.password} → roles: [${user.realmRoles.join(", ")}]`);
}

async function main(): Promise<void> {
  console.log(`Keycloak: ${config.keycloak.url}`);

  const kc = new KcAdminClient({baseUrl: config.keycloak.url, realmName: "master"});
  await kc.auth({
    username: config.keycloak.adminUser,
    password: config.keycloak.adminPassword,
    grantType: "password",
    clientId: "admin-cli",
  });

  await ensureRealm(kc);
  await ensureRealmRoles(kc);
  await ensureClient(kc, config.client);

  console.log(`\n4. Users`);
  for (const user of config.users) {
    await ensureUser(kc, user);
  }

  console.log(`\n--- Done! ---`);
  console.log(`Realm:  ${config.realm}`);
  console.log(`Issuer: ${config.keycloak.url}/realms/${config.realm}`);
  console.log(`Users:  alice/alice (user), bob/bob (admin)`);
}

main().catch((err) => {
  console.error("Setup failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
