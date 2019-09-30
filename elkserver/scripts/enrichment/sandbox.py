from .base import EnrichmentPlugin, NotFoundError, pprint
from dateutil import parser as date_parser
import re

class KnownSandboxEnrichment(EnrichmentPlugin):
    def run(self):
        for index in ["beacondb", "rtops-*"]:
            for suspect_beacon in self.run_query(index, "target_hostname.keyword :*-PC"):
                user = re.sub(' \*', '', suspect_beacon["_source"]["target_user"]).lower()

                if suspect_beacon["_source"]["target_hostname"].lower().startswith(user):
                    suspect_beacon["_source"]["tags"].extend(["sandboxes_v01", "sandbox_calculated"])
                    suspect_beacon["_source"]["tags"] = list(set(suspect_beacon["_source"]["tags"]))
                    self.update(suspect_beacon)