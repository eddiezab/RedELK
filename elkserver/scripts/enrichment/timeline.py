from .base import EnrichmentPlugin, NotFoundError
from dateutil import parser as date_parser


TIMELINE_INDEX = "beacon-timeline"


class TimelineEnrichement(EnrichmentPlugin):
    def get_timeline_hosts(self):
        query = {
            "size": "0",
            "aggs": {
                "unique_hosts": {
                    "terms": {"field": "target_hostname"}
                }
            }
        }

        try:
            return self.run_raw_query(
                TIMELINE_INDEX,
                query,
                lambda x: [y['key'] for y in x['aggregations']['unique_hosts']['buckets']])
        except:
            pass

        return []

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
                    "terms": {"field": "target_hostname"}
                }
            }
        }

        try:
            return self.run_raw_query(
                "beacondb",
                query,
                lambda x: [y['key'] for y in x['aggregations']['unique_hosts']['buckets']])
        except:
            pass

        return []

    def run(self):

        beacon_db_hosts = self.get_beacondb_hosts()
        timeline_hosts = self.get_timeline_hosts()

        removed_hosts = list(set(timeline_hosts)-set(beacon_db_hosts))

        for host in beacon_db_hosts:

            print(f"Building timeline for {host}")
            host_timeline = {
                "target_hostname": host,
                "start_date": None,
                "end_date": None,
                "detection_type": None
            }


            try:
                tmp_host_timeline = self.run_query(
                        TIMELINE_INDEX,
                        f'target_hostname:{host}'
                )

                if len(tmp_host_timeline) == 1:
                    host_timeline = tmp_host_timeline[0]

                assert len(tmp_host_timeline) <= 1
            except NotFoundError:
                pass

            new_beacons = self.run_query(
                "rtops-*",
                f"target_hostname:{host} AND cslogtype:beacon_newbeacon"
            )

            new_beacons.sort(key=lambda x: date_parser.parse(
                x["_source"]['@timestamp']))

            last_beacon = new_beacons[-1]

            last_checkin = self.run_query(
                "rtops-*", f"beacon_checkin:* AND beacon_id:{last_beacon['_source']['beacon_id']}")
            last_checkin.sort(key=lambda x: date_parser.parse(
                x["_source"]['@timestamp']))

            if len(last_checkin) == 0:
                last_checkin = new_beacons


            if '_id' in host_timeline:
                print(f"Updating timeline for {host}")
                host_timeline["_source"]["start_date"] = date_parser.parse(new_beacons[0]["_source"]["@timestamp"]).date()
                host_timeline["_source"]["end_date"] = date_parser.parse(last_checkin[-1]["_source"]["@timestamp"]).date()

                self.es.update(index=TIMELINE_INDEX,
                               doc_type=host_timeline["_type"],
                               id=host_timeline["_id"],
                               body={"doc": host_timeline["_source"]})

            else:
                print(f"Creating new timeline for {host}")
                print(host_timeline)
                host_timeline["start_date"] = date_parser.parse(new_beacons[0]["_source"]["@timestamp"]).date()
                host_timeline["end_date"] = date_parser.parse(last_checkin[-1]["_source"]["@timestamp"]).date()
                self.es.index(TIMELINE_INDEX, body=host_timeline)


        for removed_host in removed_hosts:
           self.es.delete_by_query(index=TIMELINE_INDEX, body=self.get_query_json(f"target_hostname:{removed_host}"))