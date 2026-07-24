import {z} from "zod";

// The desired-state shape for the demo realm, validated with zod so a typo fails fast.

const clientSchema = z.object({
  clientId: z.string().min(1),
  secret: z.string().min(1),
  redirectUris: z.array(z.string().url()),
  webOrigins: z.array(z.string()),
});

const userSchema = z.object({
  username: z.string().min(1),
  // dev convenience: username == password (see the user table in keycloak.config.ts).
  password: z.string().min(1),
  firstName: z.string().min(1),
  lastName: z.string().min(1),
  email: z.string().email(),
  realmRoles: z.array(z.string().min(1)).min(1),
});

export const configSchema = z.object({
  keycloak: z
    .object({
      url: z.string().url().default("http://localhost/auth"),
      adminUser: z.string().default("admin"),
      adminPassword: z.string().default("admin"),
    })
    .default({}),

  realm: z.string().default("demo"),

  // Coarse realm roles. The authorization server maps these to fine-grained scopes; Keycloak only
  // authenticates the human, so the role set stays deliberately minimal.
  realmRoles: z.array(z.string().min(1)).default(["user", "admin"]),

  // The confidential client the authorization server uses to federate the login (authorization_code).
  client: clientSchema,

  users: z.array(userSchema),
});

export type Config = z.infer<typeof configSchema>;
export type ClientConfig = z.infer<typeof clientSchema>;
export type UserConfig = z.infer<typeof userSchema>;
