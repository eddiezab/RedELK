from .base import EnrichmentPlugin, NotFoundError, pprint
from dateutil import parser as date_parser
import re

class KnownSandboxEnrichment(EnrichmentPlugin):
    state_file = "/etc/redelk/known_sandboxes.conf"

    def run(self):        
        new_sandboxes = []
        for index in ["beacondb", "rtops-*"]:
            for suspect_beacon in self.run_query(index, "NOT (tags:sandboxes_v01 OR tags:testsystems_v01) AND (target_hostname.keyword :*-PC)"):
                user = re.sub(' \*', '', suspect_beacon["_source"]["target_user"]).lower()

                if suspect_beacon["_source"]["target_hostname"].lower().startswith(user):
                    suspect_beacon["_source"]["tags"].extend(["sandboxes_v01", "sandbox_calculated"])
                    suspect_beacon["_source"]["tags"] = list(set(suspect_beacon["_source"]["tags"]))
                    self.update(suspect_beacon)

                    new_sandboxes.append(suspect_beacon["_source"]["target_hostname"])

            for state in self.state:
                if state.startswith("#"):
                    continue

                state_fields = state.split(";")

                if len(state_fields) != 4:
                    print(f"Missing  or malformed state line: {state}")
                    continue
                keyword = state_fields.pop(0)
                query = f"NOT (tags:sandboxes_v01 OR tags:testsystems_v01) AND (target_user:{state_fields[0]} {keyword} target_hostname.keyword:{state_fields[1]} {keyword} target_ipint:{state_fields[2]})"
                for suspect_beacon in self.run_query(index, query):                  
                    suspect_beacon["_source"]["tags"].extend(["sandboxes_v01", "sandbox_calculated"])
                    suspect_beacon["_source"]["tags"] = list(set(suspect_beacon["_source"]["tags"]))
                    self.update(suspect_beacon)

                    new_sandboxes.append(suspect_beacon["_source"]["target_hostname"])


        if len(new_sandboxes) > 0:
            sandboxes = ", ".join(new_sandboxes)
            self.alarm("SANDBOX ALERT", f"The following system(s) appear to be sandboxes connecting to teamservers: {sandboxes}")