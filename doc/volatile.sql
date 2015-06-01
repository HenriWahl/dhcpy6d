CREATE TABLE leases (
  address varchar(32) NOT NULL,
  active tinyint(4) NOT NULL,
  preferred_lifetime int(11) NOT NULL,
  valid_lifetime int(11) NOT NULL,
  hostname varchar(255) NOT NULL,
  type varchar(255) NOT NULL,
  category varchar(255) NOT NULL,
  ia_type varchar(255) NOT NULL,
  class varchar(255) NOT NULL,
  mac varchar(17) NOT NULL,
  duid varchar(255) NOT NULL,
  last_update datetime NOT NULL,
  preferred_until datetime NOT NULL,
  valid_until datetime NOT NULL,
  iaid varchar(8) DEFAULT NULL,
  last_message int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (address)
);

CREATE TABLE macs_llips (
  mac varchar(17) NOT NULL,
  link_local_ip varchar(39) NOT NULL,
  last_update datetime NOT NULL,
  PRIMARY KEY (mac)
);
