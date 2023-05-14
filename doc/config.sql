CREATE TABLE hosts (
  hostname varchar(255) NOT NULL,
  mac varchar(1024) DEFAULT NULL,
  class varchar(255) DEFAULT NULL,
  address varchar(255) DEFAULT NULL,
  prefix varchar(255) DEFAULT NULL,
  prefix_route_link_local INT DEFAULT 0,
  id varchar(255) DEFAULT NULL,
  duid varchar(255) DEFAULT NULL,
  PRIMARY KEY (hostname)
);
