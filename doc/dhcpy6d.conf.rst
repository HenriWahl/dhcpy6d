============
dhcpy6d.conf
============

--------------------------------------------
Configuration file for DHCPv6 server dhcpy6d
--------------------------------------------

:Author: Copyright (C) 2012-2020 Henri Wahl <h.wahl@ifw-dresden.de>
:Date:   2018-04-30
:Version: 0.7
:Manual section: 5
:Copyright: This manual page is licensed under the GPL-2 license.

Description
===========

This file contains the general settings for DHCPv6 server daemon dhcpy6d.
It follows RFC 822 style parsed by Python ConfigParser module.
It contains several sections which will be discussed in detail here.

An online documentation is also available at `<https://dhcpy6d.ifw-dresden.de/documentation/config>`_. 

Boolean settings can be set with *1|0*, *on|off* or *yes|no* values. 

Some options allow multiple values. These have to be separated by spaces.

There are 5 types of sections:

**[dhcpy6d]**
    This section contains general options like interfaces, storage and logging. Only one [dhcpy6d] section is allowed.

**[address_<address_name>]**
    There can be various *[address_<address_name>]* sections. In several address sections several address ranges and types can be defined.
    Addresses are organized in classes. For details read further down.

**[prefix_<prefix_name>]**
    There can be various *[prefix_<prefix_name>]* sections. In several prefix sections several prefix ranges and types can be defined.
    Prefixes are organized in classes. For details read further down.

**[class_<class_name>]**
    Class definitions allow to apply different addresses, time limits et al. to different types of clients.

**[bootfile_<bootfile_name>]**
    There can be various *[bootfile_<bootfile_name>]* sections. In serveral bootfile sections several tftp bootfile urls with restrictions
    to CPU architecture and user class supplied by the PXE client can be defined.

General configuration in section [dhcpy6d]
==========================================

This section contains important general options. Values are sometimes examples and not meant to be used in production
environments.

**really_do_it = yes|no**
    Let dhcpy6d **really do it** and respond to client requests - disabling might be of use for debugging and testing.
    *Default: no*

**interface = <interface> [<interface> ...]**
    The interfaces the server listens on is defined with keyword interface. Multiple interfaces have to be separated by spaces.

**mcast = <multicast-address>**
    The multicast address to listen at is ff02::1:2. Due to the facts that dhcpy6d at the moment works in local network segments only and to the restriction of MAC addresses only being usable there it will always have this value.

**port = <port>**
    Exactly the same applies to the port dhcpy6d listens on. Default is 547. Probably senseless to change it but who knows.

**serverduid = <longlongserverduid>**
    The server DUID should be configured with serverduid. If there is none dhcpy6d creates a new one at every startup.  Windows clients might run a little bit wild when server DUID changed. You are free to compose your own as long as it follows RFC 3315.
    Please note that it has to be in hexadecimal format - no octals, no "-", just like in the example below.
    The example here is a DUID-LLT (Link-layer Address Plus Time) even if it should be a DUID-TLL as timestamp comes first.
    It is composed of *DUID-type(LLT=1)* + *Hardware-type(Ethernet=1)* + *Unixtime-in-hexadecimal* + *MAC-address* what makes a *0001* + *0001* + *11fb5dc9* + *01023472a6c5* = **0001000111fb5dc901023472a6c5**.

**server_preference = <0-255>**
    The server preference determines the priority of the server. The maximum value is 255 which means highest priority.
    *Default: 255*

**user = <user>**
    For security reasons dhcpy6d can and should be run as non-root user.
    *Default: root*

**group = <group>**
    For security reasons dhcpy6d can and should be run as non-root group.
    *Default: root*

**nameserver = <nameserver-address> [<nameserver-address> ...]**
    Nameservers to be replied to request option 23 are defined with nameserver. If more than one is needed they have to be separated by spaces.
    If an address type is of category *dns* at least one nameserver has to be given here.

**domain = <domain-name>**
    The domain to be used with FQDN hostnames for option 39.

**domain_search_list = <domain-name> [<domain-name> ...]**
    Domain search lists to be used with option 24. If none is given the value of domain above is used. Multiple domains have to be separated by space or comma.

**ntp_server = <ntp_server> [<ntp_server> ...]**
    NTP servers to be used. <ntp_server> can be unicast addresses, multicast addresses or FQDNs following RFC 5908 for DHCPv6 option 56.

**log = yes|no**
    Enable logging.
    *Default: no*

**log_console = yes|no**
    Log to the console where **dhcpy6d** has been started.
    *Default: no*

**log_file = </path/to/dhcpy6d/log/file>**
    Defines the file used for logging. Will be created if it does not yet exist.

**log_syslog = yes|no**
    If logs should go to syslog it is set here.
    *Default: no*

**log_syslog_destination = syslogserver**
    An UDP syslog server may be used if **log_syslog_destination** points to it. Optionally a port other than default 514 can be set when adding ":<port>" to the destination.

**log_syslog_facility = <log-facility>**
    The default syslog facility is *daemon* but can be changed here.
    *Default: daemon*

**log_mac_llip = yes|no**
    Log discovered MAC/LLIP pairs of clients. Might be pretty verbose in larger setups and with disabled MAC/LLIP pair caching.
    *Default: no*

**store_config = file|sqlite|mysql|postgresql|none**
    Configuration of clients can be stored in a file or in a database. Databases MySQL, PostgreSQL and SQLite are supported at the moment, thus possible values are *file*, *mysql*, *postgresql*  or *sqlite*.
    To disable any client configuration source it has to be *none*.
    *Default: none*

**store_file_config = </path/to/client/conf/file>**
    File which contains the clients configuration. For details see **dhcpy6d-clients.conf(5)**.
    *Default: /etc/dhcpy6d-clients.conf*

**store_sqlite_config = /path/to/sqlite/config/file**
    SQLite database file which contains the clients configuration.
    *Default: config.sqlite*
 
**store_volatile = sqlite|mysql|postgresql**
    Volatile data like leases and the mapping between Link Local addresses and MAC addresses can be stored in MySQL, PostgreSQL or SQLite database, so the possible values are *mysql*, *postgresql* and *sqlite*.
    
**store_sqlite_volatile = /path/to/sqlite/volatile/file**
    If set to *sqlite* a SQLite database file must be defined.
    *Default: /var/lib/dhcpy6d/volatile.sqlite*

**store_db_host = <database-host>**

**store_db_db = <database-name>**

**store_db_user = <database-user>**

**store_db_password = <database-password>**
    If **store_config** and/or **store_volatile** use a database to store information it has to be set with these self-explanatory options. The same database is used for config and volatile data.

**cache_mac_llip = yes|no**
    Cache discovered MAC/LLIP pairs in database. If enabled reduces response time and opens dhcpy6d to *possible* MAC/LLIP poisoning. If disabled might increase system load.
    *Default: no*

**identification = <mac> <duid> <hostname>**
    Clients can be set to be identified by several attributes - MAC address, DUID or hostname. At least one of mac, duid or hostname is necessary. Hostname is the one sent in client request with DHCPv6 option 39. Identification is used to get the correct settings for the client from config file or database.
    Same MAC and different DUIDs might be interesting for clients with multiple OS.
    *Default: mac*

**identification_mode = match_all|match_some**
    If more than one identification attribute has been set, the identification mode can be one of *match_all* or *match_some*. The first means that all attributes have to match to identify a client and the latter is more tolerant.
    *Default: match_all*

**ignore_mac = yes|no**
    If serving only for delivering addresses regardless of classes (e.g. on PPP interface) MACs do not need to be investigated.

**dns_update = yes|no**
    Dynamically update DNS. This works at the moment only with Bind DNS, but might be extended to others, maybe via call of an external command.
    *Default: no*

**dns_update_nameserver = <nameserver-address> [<nameserver-address> ...]**

**dns_rndc_key = <rndc-key_like_in_rndc.conf>**

**dns_rndc_secret = <secret_key_like_in_rndc.conf**
    When connecting to a Bind DNS server for dynamic DNS updates its address and the necessary RNDC data must be set.

**dns_ignore_client = yes|no**
    Clients may request that they update the DNS record theirself. If their wishes shall be ignored this option has to be true.
    *Default: yes*

**dns_use_client_hostname = yes|no**
    The client hostname either comes from configuration of dhcpy6d or in the client request.
    *Default: no*

**preferred_lifetime = <seconds>**
    *Default: 5400*

**valid_lifetime = <seconds>**
    *Default: 7200*

**t1 = <seconds>**
    *Default: 2700*

**t2 = <seconds>**
    Preferred lifetime, valid lifetime, T1 and T2 in seconds are configured with the corresponding options.
    *Default: 4050*

**information_refresh_time = <seconds>**
    The lifetime of information given to clients as response to an *information-request* message.
    *Default: 6000*

**ignore_iaid = yes|no**
    Ignore IAID when looking for leases in database. Might be of use in case some clients are changing their IAD for some unknown reason.
    *Default: no*

**ignore_unknown_clients = yes|no**
    Ignore clients if no trace of them can be found in the neighbor cache.
    *Default: yes*

**request_limit = yes|no**
    Enables request limits for clients wich can be controled by *request_limit_time* and *request_limit_count*.
    *Default: no*

**request_limit_identification = mac|llip**
    Identifies clients either by MAC address or Link Local IP.
    *Default: llip*

**request_limit_time = <seconds>**
    *Default: 60*

**request_limit_count = <max_number_of_requests>**
    Requests can be limited to avoid server to be flooded by buggy clients. Set number of request during a certain time in seconds.
    *Default: 20*

**request_limit_release_time = <seconds>**
    Duration in seconds for brute force clients to stay on the blacklist.
    *Default: 7200*

**manage_routes_at_start = yes|no**
    Check prefixes at startup and call commands for adding and deleting routes respectively.
    *Default: no*


Address definitions in multiple [address_<address_name>] sections
=================================================================

The *<address_name>* part of an **[address_<address_name>]** section is an arbitrarily chosen identifier like *clients_global* or *invalid_clients_local*.
There can be many address definitions which will be used by classes. Every address definition may include several properties:

**category = mac|id|range|random|dns**
    Categories play an important role when defining patterns for addresses. An address belongs to a certain category:

    **mac**
        Uses MAC address from client request as part of address

    **eui64**
        Also uses MAC address from client as part of address, but converts it to a 64-bit extended unique identifier (EUI-64)

    **id**
        Uses ID given to client in configuration file or database as one octet of address, should be in range 0-ffff

    **range**
        Generate addresses of given range like 0-ffff

    **random**
        Randomly created 64 bit values used as host part in address
        
    **fixed**
        Use addresses from client configuration only.

    **dns**
        Ask DNS server for IPv6 address of client host

**range = <from>-<to>**
    Sets range for addresses of category *range*.

    **from**
        Starting hex number of range, minimum is 0

    **to**
        Maximum hex limit of range, highest is ffff.

**pattern = 2001:db8::$mac$|$id$|$range$|$random$**

**pattern= $prefix$::$mac$|$eui64$|$id$|$range$|$random$**
    Patterns allow to design the addresses according to their category. See examples section below to make it more clear. 

    **$mac$**
        The MAC address from the DHCPv6 request's Link Local Address found in the neighbor cache will be inserted instead of the placeholder. It will be stretched over 3 thus octets like 00:11:22:33:44:55 become 0011:2233:4455.

    **$eui64$**
        The MAC address converted to a modified 64-bit extended unique identifier (EUI-64) from the DHCPv6 request's Link Local Address found in the neighbor cache will be inserted instead of the placeholder. It will be converted according to RFC 4291 like 52:54:00:e5:b4:64 become 5054:ff:fee5:b464

    **$id$**
        If clients get an ID in client configuration file or in client configuration database this ID will fill one octet. Thus the ID has to be in the range of 0000-ffff.

    **$range$**
        If address is of category range the range defined with extra keyword *range* will be used here in place of one octet.This is why the range can span from 0000-ffff. Clients will get an address out of the given range.

    **$random64$**
        A 64 bit random address will be generated in place of this variable. Clients get a random address just like they would if privacy extensions were used. The random part will span over 4 octets.

    **$prefix**
        This placeholder can be used instead of a literal prefix and uses the prefix given at calling dhcpy6d via the *--prefix* argument like *$prefix$::$id$*.

**ia_type = na|ta**
    IA (Identity Association) types can be one of non-temporary address *na* or temporary address *ta*. Default and probably most used is *na*.
    *Default: na*

**preferred_lifetime = <seconds>**

**valid_lifetime = <seconds>**
    As default preferred and valid lifetime are set in general settings, but it is configurable individually for every address setting.

**dns_update = yes|no**
    *Default: no*

**dns_zone = <dnszone>**

**dns_rev_zone = <reverse_dnszone>**
    If these addresses should be synchronized with Bind DNS, these three settings have to be set accordingly. The nameserver for updates is set in general settings.

Default Address
---------------

The address scheme used for the default class *class_default* is by default named *address_default*.
It should be enough if *address_default* is defined, only if unknown clients should get extra nameservers etc. a *class_default* has to be set.

**[address_default]**
    Address scheme used as default for clients which do not match any other class than *class_default*.


Prefix definitions in multiple [prefix_<prefix_name>] sections
==============================================================

The *<prefix_name>* part of an **[prefix_<prefix_name>]** section is an arbitrarily chosen identifier like *customers*.
A prefix definition may contain several properties:

**category = range**
    Like addresses prefix have a category. Right now only *range* seems to make sense, similar to ranges in addresses being like 0-ffff.

**range = <from>-<to>**
    Sets range for prefix of category *range*.

    **from**
        Starting hex number of range, minimum is 0

    **to**
        Maximum hex limit of range, highest is ffff.

**pattern = 2001:db8:$range$::**

**pattern= $prefix$:$range$::**
    Patterns allow to design the addresses according to their category. See examples section below to make it more clear.

    **$range$**
        If address is of category range the range defined with extra keyword *range* will be used here in place of one octet.
        This is why the range can span from 0000-ffff. Clients will get an address out of the given range.

**length = <prefix_length>**
    Length of prefix given out to clients.

**preferred_lifetime = <seconds>**

**valid_lifetime = <seconds>**
    As default preferred and valid lifetime are set in general settings, but it is configurable individually for every prefixk setting.

**route_link_lokal = yes|no**
    As default Link Local Address of requesting client is not used as router address for external call.
    Instead the client should be able to retrieve exactly 1 address from server to be used as router for the delegated prefix.
    Alternatively the client Link Local Address might be used by enabling this option.
    *Default: no*


Class definitions in multiple [class_<class_name>] sections
===========================================================

The *<class_name>* part of an **[class_<class_name>]** section is an arbitrarily chosen identifier like *clients* or *invalid_clients*.
Clients can be grouped in classes. Different classes can have different properties, different address sets and different numbers of addresses. Classes also might have different name servers, time intervals, filters and interfaces.

A client gets the addresses, nameserver and T1/T2 values of the class which it is configured for in client configuration database or file.

**addresses = <address_name> [<address_name> ...]**
    A class can contain as many addresses as needed. Their names have to be separated by spaces. *Name* means the *name*-part of an address section like *[address_name]*.
    If a class does not contain any addresses clients won't get any address except they have one fixed defined in client configuration file or database.

**prefixes = <prefix_name> [<address_name> ...]**
    A class can contain prefixes - even most probably only one prefix will be usefull. *Name* means the *name*-part of a prefiy section.

**answer = normal|noaddress|none**
    Normally a client will get an answer, but if for whatever reason is a need to give it an *NoAddrAvail* message back or completely ignore the client it can be set here.
    *Default: normal*

**nameserver = <nameserver-address> [<nameserver-address> ...]**
    Each class can have its own nameservers. If this option is used it replaces the nameservers from general settings.

**t1 = <seconds>**

**t2 = <seconds>**
    Each class can have its own **t1** and **t2** values. The ones from general settings will be overridden. Might be of use for some invalid-but-about-to-become-valid-somehow-soon class.

**filter_hostname = <regular_expression>**

**filter_mac = <regular_expression>**

**filter_duid = <regular_expression>**
    Filters allow to apply a class to a client not by configuration but by a matching regular expression filter. Most useful might be the filtering by hostname, but maybe there is some use for DUID and MAC address based filtering too.
    The regular expressions are meant to by Python Regular Expressions. See `<https://docs.python.org/2/howto/regex.html>`_ and examples section below for details.

**interface = <interface> [<interface> ...]**
    It is possible to let a class only apply on specific interfaces. These have to be separated by spaces.

**advertise = addresses|prefixes**
    A class per default allows to advertise addresses as well as prefixes if requested. This option allows to narrow the answers down to either *addresses* or *prefixes*.
    *Default: addresses*

**call_up = <executable> [$prefix$] [$length$] [$router$]**
    When a route is requested and accepted the custom *executable* will called and the optional but senseful variables will be filled with their appropriate values.

    **$prefix$**
        Contains the prefix advertised to the client.

    **$length$**
        The prefix length.

    **$router$**
        The host which routes into the advertised prefix - of course the requesting client IPv6.

**call_down = <executable> [$prefix$] [$length$] [$router$]**
    When a route is released the custom *executable* will called and the optional but senseful variables will be filled with their appropriate values.

    **$prefix$**
        Contains the prefix advertised to the client.

    **$length$**
        The prefix length.

    **$router$**
        The host which routes into the advertised prefix - of course the requesting client IPv6.

**bootfiles = <bootfile> [<bootfile> ...]**
    List of PXE bootfiles to evaluate for clients in this client. Each value must refer a bootfile section (see below). Each bootfile is evaluated by the filter defined in the bootfile section, the first machting bootfile is chosen.

    Example:

        *bootfiles = eth1_ipxe eth1_efi64 eth1_efi32 eth1_efibc*

Default Class
-------------

At the moment every client which does not match any other class by client configuration or filter automatically matches the class "default".
This class could get an address scheme too. It should be enough if 'address_default' is defined, only if unknown clients should get extra nameservers etc. a 'class_default' has to be set.

**[class_default]**
    Default class for all clients that do not match any other class. Like any other class it might contain all options that appyl to a class.

**[class_default_<interface>]**
    If dhcpy6d listens at multiple interfaces, one can define a default class for every 'interface'.

Bootfile definitions in multiple [bootfile_<bootfile_name>] sections
====================================================================

The *<bootfile_name>* part of an **[bootfile_<bootfile_name>]** section is an arbitrarily chosen identifier like *efi32*, *bios* or *efi64*.
Each bootfile can be restricted to an architecture and/or an user class which is sent by the PXE client.

**bootfile_url = <url>**
    The bootfile URL in a format like *tftp://[2001:db8:85a3::8a2e:370:7334]/pxe.efi*. The possible protocols are dependent on the PXE client, TFTP should be supported by almost every client.

**client_architecture = <architecture>**
    Optionally restrict the bootfile to a specific CPU architecture. If the client doesn't match the requirement, the next bootfile assigned to the class definition is chosen or no bootfile is provided, if there are no
    further alternatives.

    Either the integer identifier for an architecture is possible (e.g. 0009 for EFI x86-64). The integer must consists of four numeric digits, empty digits must be written as zero (e.g. 9 => 0009). For a full list of
    possible integer identifier see `<https://tools.ietf.org/html/rfc4578#section-2.1>`_. Alternatively the well-known names of registered CPU architectures defined in RF4578 can be used:

    * Intel x86PC
    * NEC/PC98
    * EFI Itanium
    * DEC Alpha
    * Arc x86
    * Intel Lean Client
    * EFI IA32
    * EFI BC
    * EFI Xscale
    * EFI x86-64

**user_class = <user_class>**
    Optionally restrict this bootfile to PXE clients sending this user class. The *user_class* is matched against the value of the client with simple comparison (no regular expression).

    Example:

        *user_class = iPXE*

    This restricts the bootfile to the iPXE boot firmware.

Examples
========

The following paragraphs contain some hopefully helpful examples:

Minimal configuration
---------------------

    Here in this minimalistic example the server daemon listens on interface eth0. It does not use any client configuration source but answers requests with default addresses.
    These are made of the pattern fd01:db8:dead:bad:beef:$mac$ and result in addresses like fd01:db8:deaf:bad:beef:1020:3040:5060 if the MAC address of the requesting client was 10:20:30:40:50:60.

    |    
    |    [dhcpy6d]
    |    # Set to yes to really answer to clients.
    |    really_do_it = yes
    |
    |    # Interface to listen to multicast ff02::1:2.
    |    interface = eth0
    |
    |    # Some server DUID.
    |    serverduid = 0001000134824528134567366121
    |
    |    # Do not identify and configure clients.
    |    store_config = none
    |
    |    # SQLite DB for leases and LLIP-MAC-mapping.
    |    store_volatile = sqlite
    |    store_sqlite_volatile = /var/lib/dhcpy6d/volatile.sqlite
    |
    |    # Special address type which applies to all not specially.
    |    # configured clients.
    |    [address_default]
    |    # Choosing MAC-based addresses.
    |    category = mac
    |    # ULA-type address pattern.
    |    pattern = fd01:db8:dead:bad:beef:$mac$

Configuration with valid and unknown clients
--------------------------------------------

    This example shows some more complexity. Here only valid hosts will get a random global address from 2001:db8::/64.
    Unknown clients get a default ULA range address from fc00::/7.

    |    
    |    [dhcpy6d]
    |    # Set to yes to really answer to clients.
    |    really_do_it = yes
    |     
    |    # Interface to listen to multicast ff02::1:2.
    |    interface = eth0
    |
    |    # Server DUID - if not set there will be one generated every time dhcpy6d starts.
    |    # This might cause trouble for Windows clients because they go crazy about the
    |    # changed server DUID.
    |    serverduid = 0001000134824528134567366121
    |
    |    # Non-privileged user/group.
    |    user = dhcpy6d
    |    group = dhcpy6d
    |
    |    # Nameservers for option 23 - there can be several specified separated by spaces.
    |    nameserver = fd00:db8::53
    |
    |    # Domain to be used for option 39 - host FQDN.
    |    domain = example.com
    |
    |    # Domain search list for option 24 - domain search list.
    |    # If omitted the value of option "domain" above is taken as default.
    |    domain_search_list = example.com
    |
    |    # Do logging.
    |    log = yes
    |    # Log to console.
    |    log_console = no
    |    # Path to logfile.
    |    log_file = /var/log/dhcpy6d.log
    |
    |    # Use SQLite for client configuration.
    |    store_config = sqlite
    |
    |    # Use SQLite for volatile data.
    |    store_volatile = sqlite
    |
    |    # Paths to SQLite database files.
    |    store_sqlite_config = /var/lib/dhcpy6d/config.sqlite
    |    store_sqlite_volatile = /var/lib/dhcpy6d/volatile.sqlite
    |
    |    # Declare which attributes of a requesting client should be checked
    |    # to prove its identity. It is  possible to mix them, separated by spaces.
    |    identification = mac
    |
    |    # Declare if all checked attributes have to match or is it enough if
    |    # some do. Kind of senseless with just one attribute.
    |    identification_mode = match_all
    |
    |    # These lifetimes are also used as default for addresses which
    |    # have no extra defined lifetimes.
    |    preferred_lifetime = 43200
    |    valid_lifetime = 64800
    |    t1 = 21600
    |    t2 = 32400
    |
    |    # ADDRESS DEFINITION
    |    # Addresses for proper valid clients.
    |    [address_valid_clients]
    |    # Better privacy for global addresses with category random.
    |    category = random
    |    # The following pattern will result in addresses like 2001:0db8::d3f6:834a:03d5:139c.
    |    pattern = 2001:db8::$random64$
    |
    |    # Default addresses for unknown invalid clients.
    |    [address_default]
    |    # Unknown clients will get an internal ULA range-based address.
    |    category = range
    |    # The keyword "range" sets the range used in pattern.
    |    range = 1000-1fff
    |    # This pattern results in addresses like fd00::1234.
    |    pattern = fd00::$range$
    |
    |    # CLASS DEFINITION
    |
    |    # Class for proper valid client.
    |    [class_valid_clients]
    |    # At least one of the above address schemes has to be set.
    |    addresses = valid_clients
    |    # Valid clients get a different nameserver.
    |    nameserver = 2001:db8::53
    |
    |    # Default class for unknown hosts - only necessary here because of time interval settings.
    |    [class_default]
    |    addresses = default
    |    # Short interval of address refresh attempts so that a client's status
    |    # change will be reflected in IPv6 address soon.
    |    t1 = 600
    |    t2 = 900

Configuration with 2 network segments, servers, valid and unknown clients
-------------------------------------------------------------------------

    This example uses 2 network segments, one for servers and one for clients. Servers here only get local ULA addresses.
    Valid clients get 2 addresses, one local ULA and one global GUA address. This feature of DHCPv6 is at the moment only
    well supported by Windows clients. Unknown clients will get a local ULA address. Only valid clients and servers will
    get information about nameservers.


    |   
    |    [dhcpy6d]
    |    # Set to yes to really answer to clients.
    |    really_do_it = yes
    |
    |    # Interfaces to listen to multicast ff02::1:2.
    |    # eth1 - client network
    |    # eth2 - server network
    |    interface = eth1 eth2
    |
    |    # Server DUID - if not set there will be one generated every time dhcpy6d starts.
    |    # This might cause trouble for Windows clients because they go crazy about the
    |    # changed server DUID.
    |    serverduid = 0001000134824528134567366121
    |
    |    # Non-privileged user/group.
    |    user = dhcpy6d
    |    group = dhcpy6d
    |
    |    # Domain to be used for option 39 - host FQDN.
    |    domain = example.com
    |
    |    # Domain search list for option 24 - domain search list.
    |    # If omited the value of option "domain" above is taken as default.
    |    domain_search_list = example.com
    |
    |    # Do logging.
    |    log = yes
    |    # Log to console.
    |    log_console = no
    |    # Path to logfile.
    |    log_file = /var/log/dhcpy6d.log
    |
    |    # Use MySQL for client configuration.
    |    store_config = mysql
    |
    |    # Use MySQL for volatile data.
    |    store_volatile = mysql
    |
    |    # Data used for MySQL storage.
    |    store_db_host = localhost
    |    store_db_db = dhcpy6d
    |    store_db_user = dhcpy6d
    |    store_db_password = dhcpy6d
    |
    |    # Declare which attributes of a requesting client should be checked
    |    # to prove its identity. It is  possible to mix them, separated by spaces.
    |    identification = mac
    |
    |    # Declare if all checked attributes have to match or is it enough if
    |    # some do. Kind of senseless with just one attribute.
    |    identification_mode = match_all
    |
    |    # These lifetimes are also used as default for addresses which
    |    # have no extra defined lifetimes.
    |    preferred_lifetime = 43200
    |    valid_lifetime = 64800
    |    t1 = 21600
    |    t2 = 32400
    |
    |    # ADDRESS DEFINITION
    |
    |    # Global addresses for proper valid clients (GUA).
    |    [address_valid_clients_global]
    |    # Better privacy for global addresses with category random.
    |    category = random
    |    # The following pattern will result in addresses like 2001:0db8::d3f6:834a:03d5:139c.
    |    pattern = 2001:db8::$random64$
    |
    |    # Local addresses for proper valid clients (ULA).
    |    [address_valid_clients_local]
    |    # Local addresses need no privacy, so they will be based of range.
    |    category = range
    |    range = 2000-2FFF
    |    # Valid clients will get local ULA addresses from fd01::/64.
    |    pattern = fd01::$range$
    |
    |    # Servers in servers network will get local addresses based on IDs from client configuration.
    |    [address_servers]
    |    # IDs are set in client configuration database in range of 0-FFFF.
    |    category = id
    |    # Servers will get local ULA addresses from fd02::/64.
    |    pattern = fd02::$id$
    |
    |    # Default addresses for unknown invalid clients
    |    [address_default]
    |    # Unknown clients will get an internal ULA range-based address.
    |    category = range
    |    # The keyword "range" sets the range used in pattern.
    |    range = 1000-1FFF
    |    # This pattern results in addresses like fd00::1234.
    |    pattern = fd00::$range$
    |
    |    # CLASS DEFINITION
    |
    |    # Class for proper valid client.
    |    [class_valid_clients]
    |    # Clients only exist in network linked with eth1.
    |    interface = eth1
    |    # Valid clients get 2 addresses, one local ULA and one global GUA
    |    # (only works reliably with Windows clients).
    |    addresses = valid_clients_global valid_clients_local
    |    # Only valid clients get a nameserver from server network.
    |    nameserver = fd02::53
    |
    |    # Class for servers in network on eth2
    |    [class_servers]
    |    # Servers only exist in network linked with eth2.
    |    interface = eth2
    |    # Only local addresses for servers.
    |    addresses = servers
    |    # Nameserver from server network.
    |    nameserver = fd02::53
    |
    |    # Default class for unknown hosts - only necessary here because of time interval settings
    |    [class_default]
    |    addresses = default
    |    # Short interval of address refresh attempts so that a client's status
    |    # change will be reflected in IPv6 address soon.
    |    t1 = 600
    |    t2 = 900


Configuration with dynamic DNS Updates
--------------------------------------

    In this example the hostnames of valid clients will be registered in the Bind DNS server. The zones to be updated are configured for every address definition. Here only the global GUA addresses for valid clients will be updated in DNS.
    The hostnames will be taken from client configuration data - the ones supplied by the clients are ignored.

    |   
    |    [dhcpy6d]
    |    # Set to yes to really answer to clients.
    |    really_do_it = yes
    |
    |    # Interface to listen to multicast ff02::1:2.
    |    interface = eth0
    |
    |    # Server DUID - if not set there will be one generated every time dhcpy6d starts.
    |    # This might cause trouble for Windows clients because they go crazy about the
    |    # changed server DUID.
    |    serverduid = 0001000134824528134567366121
    |
    |    # Non-privileged user/group.
    |    user = dhcpy6d
    |    group = dhcpy6d
    |
    |    # Nameservers for option 23 - there can be several specified separated by spaces.
    |    nameserver = fd00:db8::53
    |
    |    # Domain to be used for option 39 - host FQDN.
    |    domain = example.com
    |
    |    # Domain search list for option 24 - domain search list.
    |    # If omited the value of option "domain" above is taken as default.
    |    domain_search_list = example.com
    |
    |    # This works at the moment only for ISC Bind nameservers.
    |    dns_update = yes
    |
    |    # RNDC key name for DNS Update.
    |    dns_rndc_key = rndc-key
    |
    |    # RNDC secret - mostly some MD5-hash. Take it from
    |    # nameservers' /etc/rndc.key.
    |    dns_rndc_secret = 0123456789012345679
    |
    |    # Nameserver to talk to.
    |    dns_update_nameserver = ::1
    |
    |    # Regarding RFC 4704 5. there are 3 kinds of client behaviour
    |    # for N O S bits:
    |    # - client wants to update DNS itself -> sends 0 0 0
    |    # - client wants server to update DNS -> sends 0 0 1
    |    # - client wants no server DNS update -> sends 1 0 0
    |    # Ignore client ideas about DNS (if at all, what name to use, self-updating...)
    |    # Here client hostname is taken from client configuration
    |    dns_ignore_client = yes
    |
    |    # Do logging.
    |    log = yes
    |    # Log to console.
    |    log_console = no
    |    # Path to logfile.
    |    log_file = /var/log/dhcpy6d.log
    |
    |    # Use SQLite for client configuration.
    |    store_config = sqlite
    |
    |    # Use SQLite for volatile data.
    |    store_volatile = sqlite
    |
    |    # Paths to SQLite database files.
    |    store_sqlite_config = config.sqlite
    |    store_sqlite_volatile = volatile.sqlite
    |
    |    # Declare which attributes of a requesting client should be checked
    |    # to prove its identity. It is  possible to mix them, separated by spaces.
    |    identification = mac
    |
    |    # ADDRESS DEFINITION
    |
    |    # Addresses for proper valid clients.
    |    [address_valid_clients]
    |    # Better privacy for global addresses with category random.
    |    category = random
    |    # The following pattern will result in addresses like 2001:0db8::d3f6:834a:03d5:139c.
    |    pattern = 2001:db8::$random64$
    |    # Update these addresses in Bind DNS
    |    dns_update = yes
    |    # Zone to update.
    |    dns_zone = example.com
    |    # Reverse zone to update
    |    dns_rev_zone = 8.b.d.0.1.0.0.2.ip6.arpa
    |
    |    # Default addresses for unknown invalid clients.
    |    [address_default]
    |    # Unknown clients will get an internal ULA range-based address.
    |    category = range
    |    # The keyword "range" sets the range used in pattern.
    |    range = 1000-1FFF
    |    # This pattern results in addresses like fd00::1234.
    |    pattern = fd00::$range$
    |
    |    # CLASS DEFINITION
    |
    |    # Class for proper valid client.
    |    [class_valid_clients]
    |    # At least one of the above address schemes has to be set.
    |    addresses = valid_clients
    |    # Valid clients get a different nameserver.
    |    nameserver = 2001:db8::53

Configuration with filter
-------------------------

    In this example the membership of a client to a class is defined by a filter for hostnames. All Windows machines have win*-names here and when requesting an address this hostname gets filtered.

    |    
    |    [dhcpy6d]
    |    # Set to yes to really answer to clients.
    |    really_do_it = yes
    |    
    |    # Interface to listen to multicast ff02::1:2.
    |    interface = eth0
    |    
    |    # Server DUID - if not set there will be one generated every time dhcpy6d starts.
    |    # This might cause trouble for Windows clients because they go crazy about the
    |    # changed server DUID.
    |    serverduid = 0001000134824528134567366121
    |    
    |    # Use no client configuration.
    |    store_config = none
    |    
    |    # Use SQLite for volatile data.
    |    store_volatile = sqlite
    |    
    |    # Paths to SQLite database file.
    |    store_sqlite_volatile = volatile.sqlite
    |    
    |    # ADDRESS DEFINITION
    |    
    |    [address_local]
    |    category = range
    |    range = 1000-1FFF
    |    pattern = fd00::$range$
    |    
    |    [address_global]
    |    category = random
    |    pattern = 2001:638::$random64$
    |    
    |    # CLASS DEFINITION
    |    
    |    [class_windows]
    |    addresses = local
    |    # Python regular expressions to be used here
    |    filter_hostname = win.* 
    |    [class_default]
    |    addresses = global

Configuration with prefixes
---------------------------

Here dhcpy6d also provides prefixes in the default class. To avoid heavy load by bad clients request limits are activated.

    |
    |    [dhcpy6d]
    |    interface = eth0
    |    server_preference = 255
    |
    |    store_config = none
    |    store_volatile = sqlite
    |    store_sqlite_volatile = /var/lib/dhcpy6d/volatile.sqlite
    |
    |    log = on
    |    log_console = yes
    |    log_syslog = yes
    |    log_file = /var/log/dhcpy6d.log
    |
    |    identification_mode = match_all
    |    identification = mac
    |
    |    nameserver = 2001:db8::53
    |    ntp_server = 2001:db8::123
    |
    |    # Mitigate ugly and aggressive clients
    |    request_limit = yes
    |    request_limit_time = 30
    |    request_limit_count = 10
    |    request_limit_identification = llip
    |    ignore_iaid = yes
    |    ignore_unknown_clients = yes
    |
    |    advertise = adresses prefixes
    |    manage_routes_at_start = yes
    |
    |    [address_default]
    |    category = mac
    |    pattern = 2001:db8::$mac$
    |
    |    [prefix_default]
    |    category = range
    |    range = 0000-ffff
    |    pattern = 2001:db8:0:$range$::
    |    route_link_local = yes
    |    length = 64
    |
    |    [class_default]
    |    addresses = default
    |    prefixes = default
    |    call_up = sudo ip -6 route add $prefix$/$length$ via $router$ dev eth0
    |    call_down = sudo ip -6 route delete $prefix$/$length$ via $router$ dev eth0

Only use fixed addresses
------------------------

If no addresses should be generated, the clients need to have an address defined in their configuration file or database. It looks like this:

    |    [example-client]
    |    hostname = example-client
    |    mac = 01:02:03:04:05:06
    |    class = fixed_address
    |    address = 2001:db8::1234

The according class of the client simply must not have any address definition an might as well stay empty:

    |
    |    [dhcpy6d]
    |    # Set to yes to really answer to clients.
    |    really_do_it = yes
    |
    |    # Interface to listen to multicast ff02::1:2.
    |    interface = eth0
    |
    |    # Some server DUID.
    |    serverduid = 0001000134824528134567366121
    |
    |    # Do not identify and configure clients.
    |    store_config = none
    |
    |    # SQLite DB for leases and LLIP-MAC-mapping.
    |    store_volatile = sqlite
    |    store_sqlite_volatile = /var/lib/dhcpy6d/volatile.sqlite
    |
    |    # Special address type which applies to all not specially.
    |    # configured clients.
    |    [address_default]
    |    # Choosing MAC-based addresses.
    |    category = mac
    |    # ULA-type address pattern.
    |    pattern = fd01:db8:dead:bad:beef:$mac$
    |    # To use the EUI-64 instead of the plain MAC address:
    |    #category = eui64
    |    #pattern = fd01:db8:dead:bad:$eui64$
    |
    |    [class_fixed_address]
    |    # just no address definiton here


Supply a PXE bootfile for different CPU architectures and user classes
----------------------------------------------------------------------

This example how to assign PXE bootfiles depending on CPU architecture and user class:

    |   [class_default_eth1]
    |   bootfiles = eth1_ipxe eth1_efi64 eth1_efi32 eth1_efibc
    |   addresses = eth1
    |   interface = eth1
    |   nameserver = fdff:cc21:56df:8bc8:5054:00ff:fec2:c5dd 2001:0470:76aa:00f5:5054:00ff:fec2:c5dd
    |   filter_mac = .*
    |
    |   [address_eth1]
    |   # Choosing EUI-64-based addresses.
    |   category = eui64
    |   # ULA-type address pattern.
    |   pattern = fdff:cc21:56df:8bc8::$eui64$
    |
    |   [bootfile_eth1_ipxe]
    |   user_class = iPXE
    |   bootfile_url = tftp://[fdff:cc21:56df:8bc8:5054:00ff:fec2:c5dd]/default.ipxe
    |
    |   [bootfile_eth1_efi32]
    |   client_architecture = 0006
    |   bootfile_url = tftp://[fdff:cc21:56df:8bc8:5054:00ff:fec2:c5dd]/efi32/ipxe.efi
    |
    |   [bootfile_eth1_efibc]
    |   client_architecture = 0007
    |   bootfile_url = tftp://[fdff:cc21:56df:8bc8:5054:00ff:fec2:c5dd]/efi64/ipxe.efi
    |
    |   [bootfile_eth1_efi64]
    |   client_architecture = 0009
    |   bootfile_url = tftp://[fdff:cc21:56df:8bc8:5054:00ff:fec2:c5dd]/efi32/ipxe.efi
    |
    |   [bootfile_eth2_ipxe]
    |   user_class = iPXE
    |   bootfile_url = tftp://[fdff:cc21:56df:fe1d:5054:00ff:fe3f:5da0]/default.ipxe
    |
    |   [bootfile_eth2_efi32]
    |   client_architecture = 0006
    |   bootfile_url = tftp://[fdff:cc21:56df:fe1d:5054:00ff:fe3f:5da0]/efi32/ipxe.efi
    |
    |   [bootfile_eth2_efibc]
    |   client_architecture = 0007
    |   bootfile_url = tftp://[fdff:cc21:56df:fe1d:5054:00ff:fe3f:5da0]/efi64/ipxe.efi
    |
    |   [bootfile_eth2_efi64]
    |   client_architecture = 0009
    |   bootfile_url = tftp://[fdff:cc21:56df:fe1d:5054:00ff:fe3f:5da0]/efi32/ipxe.efi

At first there is a check for the iPXE boot firmware, which delivers an iPXE script on success. Otherwise the iPXE binary matching to the architecture is served.

License
=======

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public
License along with this package; if not, write to the Free
Software Foundation, Inc., 51 Franklin St, Fifth Floor,
Boston, MA  02110-1301 USA

On Debian systems, the full text of the GNU General Public
License version 2 can be found in the file
*/usr/share/common-licenses/GPL-2*.


See also
========

* dhcpy6d(8)
* dhcpy6d-clients.conf(5)
* `<https://dhcpy6d.ifw-dresden.de>`_
* `<https://github.com/HenriWahl/dhcpy6d>`_
