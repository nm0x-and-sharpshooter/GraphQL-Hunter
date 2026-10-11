// ─────────────────────────────────────────────────────────────────────────────
// wordlist.ts — Curated GraphQL field & type fuzzing dictionary (Day 6)
//
// Used by the attack engine to generate field-suggestion probes and field-name
// fuzzing payloads without any external file dependency.
//
// Organised by semantic category so callers can pick relevant subsets.
// ─────────────────────────────────────────────────────────────────────────────

/** Common top-level query root fields found across GraphQL APIs. */
export const ROOT_QUERY_FIELDS: readonly string[] = [
  // User / identity
  'me', 'user', 'users', 'currentUser', 'viewer', 'profile', 'account',
  'userById', 'getUserById', 'getUser', 'getUsers',
  // Org / tenancy
  'organization', 'organisations', 'tenant', 'workspace', 'team', 'company',
  // Products / catalogue
  'product', 'products', 'item', 'items', 'catalog', 'inventory',
  // Orders / billing
  'order', 'orders', 'invoice', 'invoices', 'subscription', 'subscriptions',
  'billing', 'payment', 'payments', 'charge', 'charges',
  // Roles / permissions
  'role', 'roles', 'permission', 'permissions', 'policy', 'policies',
  'acl', 'grant', 'grants',
  // Messaging / notifications
  'message', 'messages', 'notification', 'notifications', 'alert', 'alerts',
  'conversation', 'conversations', 'thread', 'threads',
  // Settings / config
  'settings', 'config', 'configuration', 'preferences', 'flags', 'featureFlags',
  // Analytics / reporting
  'analytics', 'report', 'reports', 'metric', 'metrics', 'stat', 'stats', 'event', 'events',
  // Auth / sessions
  'session', 'sessions', 'token', 'tokens', 'apiKey', 'apiKeys',
  // Files / media
  'file', 'files', 'document', 'documents', 'upload', 'uploads', 'attachment', 'attachments',
  // Search
  'search', 'searchResults', 'query',
  // Connections (Relay-style)
  'usersConnection', 'productsConnection', 'ordersConnection',
  // Admin / internal
  'admin', 'adminUser', 'debug', 'internal', 'healthCheck', 'serviceInfo',
  // Node (Relay)
  'node', 'nodes',
];

/** Common mutation root fields. */
export const ROOT_MUTATION_FIELDS: readonly string[] = [
  // User mutations
  'createUser', 'updateUser', 'deleteUser', 'deactivateUser', 'activateUser',
  'resetPassword', 'changePassword', 'changeEmail',
  // Auth mutations
  'login', 'logout', 'signIn', 'signUp', 'register', 'refreshToken',
  'createSession', 'revokeSession', 'invalidateToken',
  // Org mutations
  'createOrganization', 'updateOrganization', 'deleteOrganization',
  'addMember', 'removeMember', 'updateRole',
  // Products
  'createProduct', 'updateProduct', 'deleteProduct', 'archiveProduct',
  // Orders
  'createOrder', 'updateOrder', 'cancelOrder', 'refundOrder',
  // Settings
  'updateSettings', 'updatePreferences', 'enableFeature', 'disableFeature',
  // Files
  'uploadFile', 'deleteFile', 'createUploadUrl',
  // Admin
  'impersonateUser', 'adminUpdateUser', 'forceLogout',
];

/** Common scalar field names (used for leaf-field fuzzing inside types). */
export const SCALAR_FIELDS: readonly string[] = [
  // IDs
  'id', 'uid', 'uuid', 'guid', 'nodeId', 'externalId', 'legacyId',
  // Identity
  'name', 'firstName', 'lastName', 'displayName', 'username', 'handle',
  'email', 'emailAddress', 'phone', 'phoneNumber', 'bio', 'description',
  // Auth / secrets
  'password', 'passwordHash', 'token', 'accessToken', 'refreshToken',
  'apiKey', 'secret', 'twoFactorSecret', 'backupCodes',
  // Roles
  'role', 'roles', 'permissions', 'isAdmin', 'isSuperAdmin', 'isStaff',
  // Status
  'status', 'state', 'active', 'enabled', 'verified', 'confirmed',
  // Timestamps
  'createdAt', 'updatedAt', 'deletedAt', 'lastLogin', 'lastActive', 'expiredAt',
  // Financial
  'balance', 'amount', 'price', 'cost', 'revenue', 'creditCard', 'stripeId',
  // Contact / address
  'address', 'street', 'city', 'country', 'zipCode', 'postalCode',
  // Links
  'avatarUrl', 'profileUrl', 'websiteUrl', 'redirectUrl',
  // Misc
  'metadata', 'tags', 'labels', 'notes', 'comment', 'ip', 'userAgent',
];

/** Fields commonly used in inline fragments and named fragments. */
export const FRAGMENT_FIELDS: readonly string[] = [
  'id', 'name', 'email', 'createdAt', 'updatedAt', 'status', 'role',
];

/** Type names commonly found in GraphQL schemas. */
export const TYPE_NAMES: readonly string[] = [
  'User', 'Account', 'Profile', 'Member', 'Admin',
  'Product', 'Item', 'Order', 'Invoice', 'Subscription',
  'Organization', 'Team', 'Workspace', 'Tenant',
  'Session', 'Token', 'ApiKey',
  'Message', 'Notification', 'Thread',
  'File', 'Upload', 'Attachment',
  'Role', 'Permission', 'Policy',
  'Settings', 'Configuration', 'FeatureFlag',
  'Analytics', 'Event', 'Report',
  'Node', 'Edge', 'Connection', 'PageInfo',
];

/** Subset of fields historically associated with sensitive data exposure. */
export const SENSITIVE_FIELDS: readonly string[] = [
  'password', 'passwordHash', 'token', 'accessToken', 'refreshToken',
  'apiKey', 'secret', 'privateKey', 'twoFactorSecret', 'backupCodes',
  'creditCard', 'ssn', 'socialSecurity', 'bankAccount', 'stripeId',
  'email', 'phone', 'address', 'ipAddress', 'userAgent',
  'isAdmin', 'isSuperAdmin', 'isStaff', 'permissions', 'roles',
  'balance', 'revenue', 'salary',
  'debug', 'internal', 'metadata',
];

// ── Day 7: Injection \u0026 Transport Probe Wordlists ─────────────────────────────

/**
 * Non-destructive SQL injection probe strings.
 * Designed to trigger syntax errors or boolean-based responses without
 * modifying data (no DROP, DELETE, UPDATE, INSERT).
 */
export const SQLI_PROBES: readonly string[] = [
  "' OR '1'='1",
  "1' ORDER BY 1--",
  "' UNION SELECT NULL--",
  "admin'--",
  '" OR ""="',
  "1; SELECT 1--",
  "' AND 1=1--",
  "' AND 1=2--",
  "1' OR '1'='1' /*",
  "') OR ('1'='1",
];

/**
 * NoSQL injection probes (MongoDB / CouchDB operators).
 * Sent as variable values — the variable fuzzer JSON-encodes them where applicable.
 */
export const NOSQLI_PROBES: readonly string[] = [
  '{"$gt": ""}',
  '{"$ne": null}',
  '{"$regex": ".*"}',
  '{"$where": "1==1"}',
  '{"$exists": true}',
];

/**
 * Server-Side Template Injection (SSTI) and Expression Language probes.
 * We look for reflected computation results (e.g. "49" for 7*7).
 */
export const SSTI_PROBES: readonly string[] = [
  '${7*7}',
  '{{7*7}}',
  '#{7*7}',
  '<%= 7*7 %>',
  '${7*7}',
  '{{constructor.constructor("return 7*7")()}}',
];

/** Variable names commonly used as filter/search inputs (injection targets). */
export const INJECTABLE_VARIABLE_NAMES: readonly string[] = [
  'id', 'userId', 'accountId', 'email', 'username',
  'filter', 'where', 'search', 'query', 'q',
  'sort', 'orderBy', 'limit', 'offset', 'skip',
  'input', 'data', 'name', 'title', 'slug',
  'key', 'token', 'code', 'password',
];

/**
 * Error message regex patterns indicating backend database or template engine leaks.
 * Each pattern is compiled to a RegExp by the injection scanner.
 */
export const INJECTION_ERROR_PATTERNS: readonly { pattern: string; label: string }[] = [
  // PostgreSQL
  { pattern: 'syntax error at or near',         label: 'PostgreSQL syntax error' },
  { pattern: 'unterminated quoted string',       label: 'PostgreSQL unterminated string' },
  { pattern: 'invalid input syntax',             label: 'PostgreSQL invalid input' },
  // MySQL
  { pattern: 'check the manual that corresponds to your MySQL', label: 'MySQL syntax error' },
  { pattern: 'You have an error in your SQL syntax',            label: 'MySQL syntax error' },
  { pattern: 'Unknown column',                                  label: 'MySQL unknown column' },
  // SQLite
  { pattern: 'unrecognized token',  label: 'SQLite unrecognized token' },
  { pattern: 'incomplete input',    label: 'SQLite incomplete input' },
  { pattern: 'near ".*": syntax error', label: 'SQLite syntax error' },
  // MongoDB / Mongoose
  { pattern: 'Cast to ObjectId failed',  label: 'MongoDB ObjectId cast error' },
  { pattern: 'MongoError',               label: 'MongoDB driver error' },
  { pattern: 'MongoServerError',         label: 'MongoDB server error' },
  { pattern: '\\$where is not allowed',  label: 'MongoDB $where blocked' },
  // Template engines
  { pattern: 'TemplateSyntaxError',   label: 'Template syntax error' },
  { pattern: 'UndefinedError',        label: 'Template undefined error' },
  // Generic
  { pattern: 'stack trace',    label: 'Stack trace leaked' },
  { pattern: 'SQLSTATE',       label: 'SQL state error code leaked' },
  { pattern: 'at \\w+\\.\\w+ \\(', label: 'Stack trace (Node.js / Java)' },
];

/**
 * Custom directive names to test for authorization bypass.
 * These are directives commonly used by auth middleware (e.g. Apollo auth directives).
 */
export const AUTH_DIRECTIVE_PROBES: readonly string[] = [
  '@admin',
  '@internal',
  '@auth(role: "ADMIN")',
  '@auth(role: "admin")',
  '@authorized',
  '@requireAuth',
  '@hasRole(role: "ADMIN")',
  '@isAuthenticated',
];

