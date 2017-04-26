CREATE TABLE leases (
  address varchar(32) NOT NULL,
  active smallint NOT NULL,
  preferred_lifetime int NOT NULL,
  valid_lifetime int NOT NULL,
  hostname varchar(255) NOT NULL,
  type varchar(255) NOT NULL,
  category varchar(255) NOT NULL,
  ia_type varchar(255) NOT NULL,
  class varchar(255) NOT NULL,
  mac varchar(17) NOT NULL,
  duid varchar(255) NOT NULL,
  last_update bigint NOT NULL,
  preferred_until bigint NOT NULL,
  valid_until bigint NOT NULL,
  iaid varchar(8) DEFAULT NULL,
  last_message int NOT NULL DEFAULT 0,
  PRIMARY KEY (address)
);

CREATE TABLE macs_llips (
  mac varchar(17) NOT NULL,
  link_local_ip varchar(39) NOT NULL,
  last_update bigint NOT NULL,
  PRIMARY KEY (mac)
);

CREATE TABLE meta (
  item_key varchar(255) NOT NULL,
  item_value varchar(255) NOT NULL,
  PRIMARY KEY (item)
);

