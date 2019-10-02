from .base import EnrichmentPlugin, NotFoundError, pprint
from dateutil import parser as date_parser
import re

class KnownAssetEnrichment(EnrichmentPlugin):
    tags = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.new_assets = []

    def raise_alert(self):
        pass

    def run_additional_asset_identification(self, index):
        pass

    def run(self):        
        for index in ["beacondb", "rtops-*"]:

            self.run_additional_asset_identification(index)

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
                    suspect_beacon["_source"]["tags"].extend(self.tags)
                    suspect_beacon["_source"]["tags"] = list(set(suspect_beacon["_source"]["tags"]))
                    self.update(suspect_beacon)

                    self.new_assets.append(suspect_beacon["_source"]["target_hostname"])

        self.raise_alert()


class KnownSandboxEnrichment(KnownAssetEnrichment):
    tags = ["sandboxes_v01", "sandbox_calculated"]
    state_file = "/etc/redelk/known_sandboxes.conf"

    def run_additional_asset_identification(self, index):        
        tags = list(self.tags)
        tags.append("sandbox_calculated")

        for suspect_beacon in self.run_query(index, "NOT (tags:sandboxes_v01 OR tags:testsystems_v01) AND (target_hostname.keyword :*-PC)"):
            user = re.sub(' \*', '', suspect_beacon["_source"]["target_user"]).lower()

            if suspect_beacon["_source"]["target_hostname"].lower().startswith(user):
                suspect_beacon["_source"]["tags"].extend(tags)
                suspect_beacon["_source"]["tags"] = list(set(suspect_beacon["_source"]["tags"]))
                self.update(suspect_beacon)

                self.new_assets.append(suspect_beacon["_source"]["target_hostname"])
         
    def raise_alert(self):
        if len(self.new_assets) > 0:
            sandboxes = ", ".join(self.new_assets)
            self.alarm("SANDBOX ALERT", f"The following system(s) appear to be sandboxes connecting to teamservers: {sandboxes}")


class KnownTestSystemsEnrichment(KnownAssetEnrichment):
    tags = ["testsystems_v01"]
    state_file = "/etc/redelk/known_testsystems.conf"