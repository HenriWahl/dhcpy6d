import os
import sys
import tempfile
import types
import unittest


volatile_db = tempfile.NamedTemporaryFile(delete=False)
volatile_db.close()
config = tempfile.NamedTemporaryFile("w", delete=False)
config.write(
    "[dhcpy6d]\ninterface = eth0\nignore_interface = yes\n"
    "store_config = none\nstore_sqlite_volatile = {}\n".format(volatile_db.name)
)
config.write("cleaning_interval = 3600\n")
config.close()
sys.argv = [sys.argv[0], "--config", config.name]

dns = types.ModuleType("dns")
for name in ("query", "reversename", "resolver", "update", "tsigkeyring"):
    module = types.ModuleType("dns." + name)
    setattr(dns, name, module)
    sys.modules["dns." + name] = module
sys.modules["dns"] = dns
dns.resolver.NoAnswer = type("NoAnswer", (Exception,), {})
dns.resolver.NoNameservers = type("NoNameservers", (Exception,), {})
dns.resolver.Resolver = type("Resolver", (), {"__init__": lambda self: None})

original_chown = os.chown
os.chown = lambda *_args, **_kwargs: None
from dhcpy6d.client import Client
from dhcpy6d.client.reuse_lease import reuse_lease
from dhcpy6d.config import cfg
os.chown = original_chown


class TestFixedPrefixRenew(unittest.TestCase):
    def test_restores_fixed_prefix_when_renew_contains_empty_ia_pd(self):
        class ClientConfig:
            CLASS = "fixed_eth0"
            HOSTNAME = "iserv"
            PREFIX = [{"address": "2001:db8:838:8f00::", "length": "63"}]

        class Class:
            INTERFACE = ["eth0"]
            ANSWER = "normal"
            ADVERTISE = ["prefixes"]
            PREFIXES = []

        class Transaction:
            interface = "eth0"
            ia_options = [3, 25]
            addresses = ["20010db808388fa3000000000000000002"]
            prefixes = []

        old_classes = cfg.CLASSES
        cfg.CLASSES = {"fixed_eth0": Class()}
        try:
            client = Client()
            client.client_class = "fixed_eth0"
            reuse_lease(client=client, client_config=ClientConfig(), transaction=Transaction())
            self.assertEqual(
                [(prefix.PREFIX, prefix.LENGTH) for prefix in client.prefixes],
                [("2001:db8:838:8f00::", "63")],
            )
        finally:
            cfg.CLASSES = old_classes


if __name__ == "__main__":
    unittest.main()
