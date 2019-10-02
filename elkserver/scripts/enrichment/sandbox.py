from .base import EnrichmentPlugin, NotFoundError, pprint
from dateutil import parser as date_parser
import re

class KnownSandboxEnrichment(EnrichmentPlugin):
    state_file = "/etc/redelk/known_sandboxes.conf"

    def run(self):        
        new_sandboxes = []
        for index in ["beacondb", "rtops-*"]:
            for suspect_beacon in self.run_query(index, "target_hostname.keyword :*-PC"):
                user = re.sub(' \*', '', suspect_beacon["_source"]["target_user"]).lower()

                if suspect_beacon["_source"]["target_hostname"].lower().startswith(user):
                    suspect_beacon["_source"]["tags"].extend(["sandboxes_v01", "sandbox_calculated"])
                    suspect_beacon["_source"]["tags"] = list(set(suspect_beacon["_source"]["tags"]))
                    self.update(suspect_beacon)

                    new_sandboxes.append(suspect_beacon["_source"]["target_hostname"])

            for state in self.state:
                state_fields = state.split(";")
                keyword = state_fields.pop()
                for suspect_beacon in self.run_query(index, f" {keyword} ".join(state_fields)):                  
                    suspect_beacon["_source"]["tags"].extend(["sandboxes_v01", "sandbox_calculated"])
                    suspect_beacon["_source"]["tags"] = list(set(suspect_beacon["_source"]["tags"]))
                    self.update(suspect_beacon)

                    new_sandboxes.append(suspect_beacon["_source"]["target_hostname"])


        if len(new_sandboxes) > 0:
            sandboxes = ", ".join(new_sandboxes)
            self.alarm("SANDBOX ALERT", f"The following system(s) appear to be sandboxes connecting to teamservers: {sandboxes}")