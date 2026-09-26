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
