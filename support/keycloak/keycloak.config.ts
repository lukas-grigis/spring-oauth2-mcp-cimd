import type {Config} from "./config.js";

// The single source of truth for the demo realm. Re-running the setup converges Keycloak to this.

const config: Config = {
  keycloak: {
    // Keycloak lives under /auth behind Traefik (HTTP).
    url: "http://localhost/auth",
    adminUser: "admin",
    adminPassword: "admin", // demo only — use environment variables or a secrets manager in production
  },

  realm: "demo",

  realmRoles: ["user", "admin"],

  // The authorization server federates the human login through this confidential client.
  client: {
    clientId: "keycloak",
    secret: "keycloak-dev-secret", // demo only — must match the authorization server's UPSTREAM_CLIENT_SECRET
    redirectUris: ["http://localhost:9000/login/oauth2/code/keycloak"],
    webOrigins: ["http://localhost:9000"],
  },

  // Two personas. alice is a plain user; bob is an admin. The role each carries is what the
  // authorization server turns into scopes, so it decides what each can do over MCP.
  users: [
    {
      username: "alice",
      password: "alice",
      firstName: "Alice",
      lastName: "Anderson",
      email: "alice@example.com",
      realmRoles: ["user"],
    },
    {
      username: "bob",
      password: "bob",
      firstName: "Bob",
      lastName: "Brown",
      email: "bob@example.com",
      realmRoles: ["admin"],
    },
  ],
};

export default config;
