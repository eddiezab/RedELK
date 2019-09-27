from .base import EnrichmentPlugin
from dateutil import parser as date_parser


TIMELINE_INDEX = "beacon-timeline"


class TimelineEnrichement(EnrichmentPlugin):
    def get_timeline_hosts(self):
        query = {
            "size": "0",
            "aggs": {
                "unique_hosts": {
                    "terms": {"field": "target_hostname.keyword"}
                }
            }
        }

        unique_hosts = self.run_raw_query(
            TIMELINE_INDEX,
            query,
            lambda x: [y['key'] for y in x['aggregations']['unique_hosts']['buckets']])

        return unique_hosts

    def get_beacondb_hosts(self):
        query = {
            "size": "0",
            "query": {
                "bool": {
                    "must_not": [
                        {
                            "match_phrase": {
                                "tags.keyword": "testsystems_v01"
                            }
                        },
                        {
                            "match_phrase": {
                                "tags.keyword": "sandboxes_v01"
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }},
            "aggs": {
                "unique_hosts": {
                    "terms": {"field": "target_hostname.keyword"}
                }
            }
        }

        unique_hosts = self.run_raw_query(
            "beacondb",
            query,
            lambda x: [y['key'] for y in x['aggregations']['unique_hosts']['buckets']])

        return unique_hosts

    def run(self):

        beacon_db_hosts = self.get_beacondb_hosts()
        timeline_hosts = self.get_timeline_hosts()

        removed_hosts = list(set(beacon_db_hosts) - set(timeline_hosts))

        for host in beacon_db_hosts:

            print(f"Building timeline for {host}")
            host_timeline = {
                "target_hostname": host,
                "start_date": None,
                "end_date": None,
                "detection_type": None
            }

            try:
                host_timeline = self.run_query(
                    TIMELINE_INDEX,
                    f'target_hostname.raw:{host}'
                )[0]
            except:
                pass

            host_checkins = self.run_query(
                "rtops-*", f"target_hostname.raw:{host} AND beacon_checkin:*")

            if len(host_checkins) == 0:
                print(f"No host check-ins for {host}")
                continue

            host_checkins.sort(key=lambda x: date_parser.parse(
                x["_source"]['@timestamp']))

            if '_id' in host_timeline:
                print(f"Updating timeline for {host}")
                host_timeline["_source"]["start_date"] = host_checkins[0]["_source"]["@timestamp"]
                host_timeline["_source"]["end_date"] = host_checkins[-1]["_source"]["@timestamp"]

                self.es.update(index=TIMELINE_INDEX,
                               doc_type=host_timeline["_type"],
                               id=host_timeline["_id"],
                               body={"doc": host_timeline["_source"]})

            else:
                print(f"Creating new timeline for {host}")
                print(host_timeline)
                host_timeline["start_date"] = host_checkins[0]["_source"]["@timestamp"]
                host_timeline["end_date"] = host_checkins[-1]["_source"]["@timestamp"]
                self.es.index(TIMELINE_INDEX, body=host_timeline)


