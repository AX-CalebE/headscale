-- Database created by headscale at 520eb6f9, the commit before the
-- 202611161200-credentials-federated-identity migration: NewHeadscaleDatabase
-- ran InitSchema, then the db package's own functions created the user, the
-- pre-auth keys, the nodes, the OAuth client and its access token. Node 2 and
-- credential 6 were then deleted, so both sqlite_sequence counters run past
-- their tables' max ids. Dumped with `.dump`.
--
-- Node 1 holds pre-auth key credential 1:
--   hskey-auth-7c14277c0a36-3784787b3d8f9ee1c7add278f71e97f1c06db8a03b312e2062f048f34c42020a
-- OAuth client 6eb0cff8ab48 (credential 4):
--   hskey-client-6eb0cff8ab48-343d5bad0a2161508daca4c9321ba815e335354f8ca5fd7336dc7e453c59079b
-- Its access token (credential 5):
--   hskey-oauthtok-cff564c0cbb5-474d6e5eacd70cf7a6b0fd4db21d484daa995a4dabe9a07cb2389a981208b95c
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `database_versions` (`id` integer PRIMARY KEY AUTOINCREMENT,`version` text NOT NULL,`updated_at` datetime);
CREATE TABLE `migrations` (`id` text,PRIMARY KEY (`id`));
INSERT INTO migrations VALUES('SCHEMA_INIT');
INSERT INTO migrations VALUES('202606181200-recover-null-tags-node-user-id');
INSERT INTO migrations VALUES('202606191500-api-key-user-id');
INSERT INTO migrations VALUES('202606191501-pre-auth-key-description');
INSERT INTO migrations VALUES('202606201200-pre-auth-key-revoked');
INSERT INTO migrations VALUES('202606211200-oauth-clients-and-tokens');
INSERT INTO migrations VALUES('202607241200-clear-tagged-node-expiry');
INSERT INTO migrations VALUES('202609231200-create-credentials');
INSERT INTO migrations VALUES('202609231300-migrate-to-credentials');
INSERT INTO migrations VALUES('202610211200-node-auto-approved-routes');
INSERT INTO migrations VALUES('202610211300-node-ephemeral');
INSERT INTO migrations VALUES('202610221200-credential-created-by-token');
INSERT INTO migrations VALUES('202611041200-node-last-control-address');
CREATE TABLE `users` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`name` text,`display_name` text,`email` text,`provider_identifier` text,`provider` text,`profile_pic_url` text);
INSERT INTO users VALUES(1,'2026-11-17 03:56:00.972669546+00:00','2026-11-17 03:56:00.972669546+00:00',NULL,'user1','','',NULL,'','');
CREATE TABLE credentials(
  id integer PRIMARY KEY AUTOINCREMENT,
  kind text NOT NULL CHECK(kind IN ('api','authkey','oauth_client','oauth_token')),
  identifier text,
  hash blob,
  user_id integer,
  description text,
  scopes text,
  tags text,
  reusable numeric,
  ephemeral numeric DEFAULT false,
  used numeric DEFAULT false,
  last_seen datetime,
  client_id text,
  created_at datetime,
  expiration datetime,
  revoked datetime,
  created_by_token numeric DEFAULT false,

  CONSTRAINT fk_credentials_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT chk_credentials_hash CHECK(hash IS NOT NULL OR revoked IS NOT NULL),
  CONSTRAINT chk_credentials_hash_format CHECK(hash IS NULL OR substr(CAST(hash AS TEXT), 1, 1) = '$')
);
INSERT INTO credentials VALUES(1,'authkey','7c14277c0a36',X'247368613235362461616636323739343936666638643061633661633832346638633037663865356535333165623933646537393363363235653039636233663637306330623139',1,'',NULL,'[]',0,0,0,NULL,'','2026-11-17 03:56:00.974221421+00:00','2099-01-01 00:00:00+00:00',NULL,0);
INSERT INTO credentials VALUES(2,'authkey','af07c2231cd3',X'247368613235362434313032376464313833346161623835313134313863356434366134626139393632393038386330633664663661356162303332343731323135333137356535',1,'',NULL,'[]',0,0,0,NULL,'','2026-11-17 03:56:00.975164588+00:00',NULL,NULL,0);
INSERT INTO credentials VALUES(3,'authkey','322fe6f2675d',X'247368613235362433333939656537653534303933353530613533616361633039663036396138643034633464663639663331663434306236326164343438613966376264636232',1,'',NULL,'[]',0,0,0,NULL,'','2026-11-17 03:56:00.97923588+00:00',NULL,NULL,0);
INSERT INTO credentials VALUES(4,'oauth_client','6eb0cff8ab48',X'247368613235362432633866646531613536333431376165313765623237633063636131303961333435383232316533303039656435353636376562663561666232643461626335',1,'ci','["auth_keys"]','["tag:ci"]',0,0,0,NULL,'','2026-11-17 03:56:00.98239863+00:00',NULL,NULL,0);
INSERT INTO credentials VALUES(5,'oauth_token','cff564c0cbb5',X'247368613235362437363864323931626366383362303135396364393564616461323334336361613031643830663866623361373030613339633762353237323363653263396465',NULL,'','["auth_keys"]','["tag:ci"]',0,0,0,NULL,'6eb0cff8ab48','2026-11-17 03:56:00.983275963+00:00','2099-01-01 00:00:00+00:00',NULL,0);
CREATE TABLE `nodes` (`id` integer PRIMARY KEY AUTOINCREMENT,`machine_key` text,`node_key` text,`disco_key` text,`endpoints` text,`host_info` text,`ipv4` text,`ipv6` text,`last_control_address` text,`hostname` text,`given_name` varchar(63),`user_id` integer,`register_method` text,`tags` text,`auth_key_id` integer,`ephemeral` numeric DEFAULT false,`expiry` datetime,`last_seen` datetime,`approved_routes` text,`auto_approved_routes` text,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,CONSTRAINT `fk_nodes_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,CONSTRAINT `fk_nodes_auth_key` FOREIGN KEY (`auth_key_id`) REFERENCES `credentials`(`id`));
INSERT INTO nodes VALUES(1,'mkey:130ca2d2320855aa7204561a63d20a22ce26f891f95f1e9e649f49900d73422c','nodekey:80695c2b707e73f9db960204fa41f68ba01c4d7ff3c3ac63cf7c0a65eb54a869','discokey:c0c5b042084e8168ab0e3f95373e833f9054cd54ea41b1227af65979a211d30e',NULL,NULL,'100.64.0.1','fd7a:115c:a1e0::1',NULL,'node1','node1',1,'authkey',NULL,1,0,NULL,NULL,NULL,NULL,'2026-11-17 03:56:00.976169546+00:00','2026-11-17 03:56:00.97845638+00:00',NULL);
CREATE TABLE `policies` (`id` integer PRIMARY KEY AUTOINCREMENT,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`data` text);
INSERT INTO sqlite_sequence VALUES('users',1);
INSERT INTO sqlite_sequence VALUES('credentials',6);
INSERT INTO sqlite_sequence VALUES('nodes',2);
CREATE UNIQUE INDEX idx_credentials_identifier ON credentials(kind, identifier);
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE INDEX idx_policies_deleted_at ON policies(deleted_at);
CREATE UNIQUE INDEX idx_provider_identifier ON users(provider_identifier) WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier);
CREATE UNIQUE INDEX idx_name_no_provider_identifier ON users(name) WHERE provider_identifier IS NULL;
CREATE INDEX idx_nodes_auth_key_id ON nodes(auth_key_id);
COMMIT;
