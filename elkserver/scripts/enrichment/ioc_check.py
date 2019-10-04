from .base import EnrichmentPlugin, NotFoundError, pprint
from dateutil import parser as date_parser
from datetime import datetime
import re
import requests
from collections import deque

class IOCEnrichment(EnrichmentPlugin):
    state_file = "/etc/redelk/custom_ioc.conf"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run(self):
        cs_ioc_query = {
            "size": "0",
            "aggs": {
                "ioc_checksums": {
                    "terms": {"field": "ioc_hash.keyword"}
                }
            }
        }

        custom_md5s = []

        for line in self.state:
            line_match = re.match(r"([^# ]+)(.*)", line)
            if line_match is not None:
                md5, filename = line_match.groups()
                custom_md5s.append((md5, [filename.strip()]))

        iocs = {}
        for cs_ioc in self.run_query("rtops-*", "ioc_hash:*"):
            if cs_ioc["_source"]["ioc_hash"] in iocs:
                iocs[cs_ioc["_source"]["ioc_hash"]]['filenames'].append(cs_ioc["_source"]["ioc_name"])
            else:
                iocs[cs_ioc["_source"]["ioc_hash"]] = {"filenames": [cs_ioc["_source"]["ioc_name"]]}
            
        for k, v in iocs.items():
            custom_md5s.append((k, v['filenames']))

        self.update_ioc_index(custom_md5s)
        
        checkable_iocs = self.get_checkable_iocs()

        max_len = len(checkable_iocs) if len(checkable_iocs) <=5 else 5
        while max_len != 0:
            idx = 0
            process_slice = []
            while idx < max_len:
                process_slice.append(checkable_iocs.pop())
                idx += 1
            self.check_vt(process_slice)

            max_len = len(checkable_iocs) if len(checkable_iocs) <=5 else 5






    def get_checkable_iocs(self):
        check_time = datetime.now()
        untriggered_iocs = []
        for ioc in self.run_query("custom-ioc", "NOT date_submitted:*"):
            if "last_checked" in ioc["_source"]:
                ioc["_source"]["last_checked"] = check_time.strftime("%Y-%m-%dT%H:%M:%S")
                last_check_time = date_parser.parse(ioc["_source"]["last_checked"])
                if (check_time - last_check_time).total_seconds() >= (15 * 60):
                    untriggered_iocs.append(ioc)
            else:
                ioc["_source"]["last_checked"] = check_time.strftime("%Y-%m-%dT%H:%M:%S")
                untriggered_iocs.append(ioc)

        return untriggered_iocs


    def update_ioc_index(self,md5s):
        query = {
            "size": "0",
            "aggs": {
                "ioc_checksums": {
                    "terms": {"field": "md5.keyword"}
                }
            }
        }

        stored_iocs = self.run_raw_query("custom-ioc", query, lambda x: [y['key'] for y in x['aggregations']['ioc_checksums']['buckets']])
        new_iocs = list(set([md5[0] for md5 in md5s]) - set(stored_iocs))

        for new_ioc in new_iocs:
            doc = {
                "md5": new_ioc,
                "filenames": list(filter(lambda x: x[0] == new_ioc, md5s))[0][1]
            }

            self.es.index("custom-ioc", doc)

    def check_vt(self, iocs):
        md5s = ",".join([ ioc["_source"]["md5"] for ioc in iocs ])
        params = {
            'apikey': "01e9966657e16d923a0da5ccaa301ebe2a5b289b49f3ac939684cee03da62574", 
            'resource': md5s
            }
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent" : "python"
        }
        response = requests.get(
            'https://www.virustotal.com/vtapi/v2/file/report',
            params=params,
            headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            if not isinstance(json_response, list):
                json_response = [json_response]
        else:
            json_response = None

        alert_iocs = []

        for ioc in iocs:            
            for vt_ioc in json_response:
                if vt_ioc["resource"] == ioc["_source"]["md5"]:
                    ioc["_source"]["vt"] = vt_ioc

                    if "positives" in vt_ioc and vt_ioc["positives"] > 0:
                        ioc["_source"]["date_submitted"] = date_parser.parse(vt_ioc["scan_date"]).strftime("%Y-%m-%dT%H:%M:%S")
                    self.update(ioc)
                    alert_iocs.extend(ioc["_source"]["filenames"])
                    continue

        if len(alert_iocs) > 0:
            ioc_files = ", ".join(list(set(alert_iocs)))
            self.alarm("IOCs Reported", f"The following IOCs have been reported to VT recently: {ioc_files}")