from elasticsearch import Elasticsearch
import json

def pprint(r):
    print(json.dumps(r, indent=2, sort_keys=True))

class EnrichmentPlugin(object):
    es = Elasticsearch()
    config_file = None
    config = None

    state_file = None
    state = []

    def __init__(self, *args, **kwargs):
        if self.config_file:
            with open(self.config_file) as json_data:
                self.config = json.load(json_data)

        if self.state_file:
            try:
                with open(self.state_file) as state_data:
                    self.state = [ line.rstrip() for line in state_data.readlines() ]
            except:
                pass

        self.queue_size = kwargs.get("queue_size", 10000)

    def get_query_json(self, query):
        return {
            "query": {
                "query_string": {
                    "query": query
                }
            }
        }

    def run_query(self, index_pattern, query, transform_result=False):
        result = self.es.search(
            index=index_pattern,
            size=self.queue_size,
            body=self.get_query_json(query)
        )

        if transform_result:
            return transform_result(result["hits"]["hits"])

        return result["hits"]["hits"]

    def run(self):
        pass


class ASNEnrichmentPlugin(EnrichmentPlugin):
    state_file = "/etc/redelk/known_asns.conf"

    index_pattern_filter_maps = [{
        "index_pattern": "beacondb",
        "query": "geoip.asn:* AND NOT beacon_origin:*",
        "result_map": "_source.geoip.asn"
    },
    {
        "index_pattern": "redirector-*",
        "query": "geoip.asn:* AND NOT beacon_origin:*",
        "result_map": "_source.geoip.asn"
    }]

    def run(self):
        updated_records = []
        for filter_map in self.index_pattern_filter_maps:            
            for result in self.run_query(filter_map["index_pattern"], filter_map["query"]):
                value = result
                for key in filter_map["result_map"].split("."):
                    value = value[key]
                    
                if str(value) in self.state:
                    result["_source"]["beacon_origin"] = "office"

                    self.es.update(index=result["_index"],
                                doc_type=result["_type"],
                                id=result["_id"],
                                body={"doc":result["_source"]})

                    updated_records.append(result)

        return updated_records
