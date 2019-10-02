from .base import EnrichmentPlugin, NotFoundError, pprint
from dateutil import parser as date_parser


TIMELINE_INDEX = "beacon-timeline"


class BeaconIdTagEnrichment(EnrichmentPlugin):
    def get_newbeacon_events(self):
        beacon_history = {}
        for newbeacon in self.run_query("rtops-*", "cslogtype:beacon_newbeacon"):
            if newbeacon["_source"]["beacon_id"] not in beacon_history:
                beacon_history[newbeacon["_source"]["beacon_id"]] = [newbeacon]
            else:
                beacon_history[newbeacon["_source"]
                               ["beacon_id"]].append(newbeacon)

        return beacon_history

    def get_untagged_rtops_by_id(self, beacon_id):
        return self.run_query("rtops-*", f"beacon_id:{beacon_id} AND NOT target_hostname:*")

    def get_untagged_rtops_by_id_and_timerange(self, beacon_id, beacon):
        query = {
            "query": {
                "bool": {
                    "must": {
                        "range": {
                            "@timestamp": {
                                "gte": beacon["_source"]["@timestamp"],
                                "lte": "now"
                            }
                        }
                    },
                    "must_not": {
                        "exists": {
                            "field": "target_hostname"
                        }
                    },
                    "filter": {
                        "term": {
                            "beacon_id": beacon_id
                        }
                    }
                }
            }
        }

        return self.run_raw_query("rtops-*", query)

    def tag_beacon(self, source_beacon, beacon_event):
        # for untagged in self.get_untagged_rtops_by_id(beacon_id):
        for field in ["target_hostname", "target_ipext", "target_os", "target_osversion", "target_pid", "target_user"]:
            if field in source_beacon["_source"]:
                beacon_event["_source"][field] = source_beacon["_source"][field]

        self.update(beacon_event)

    def tag_beacon_events(self, source_beacon, beacon_events):
        for beacon_event in beacon_events:
            self.tag_beacon(source_beacon, beacon_event)

    def run(self):
        for beacon_id, beacon_info in self.get_newbeacon_events().items():
            if len(beacon_info) == 1:
                self.tag_beacon_events(
                    beacon_info[0], self.get_untagged_rtops_by_id(beacon_id))
            else:
                beacon_host_names = list(
                    set([b["_source"]["target_hostname"] for b in beacon_info]))
                if len(beacon_host_names) == 1:
                    for beacon in beacon_info:
                        self.tag_beacon_events(
                            beacon, self.get_untagged_rtops_by_id(beacon_id))
                else:
                    print(beacon_id, beacon_host_names)
                    beacon_info.sort(key=lambda x: date_parser.parse(
                        x["_source"]['@timestamp']))
                    beacon_info.reverse()
                    for beacon in beacon_info:
                        beacon_events = self.get_untagged_rtops_by_id_and_timerange(
                            beacon_id, beacon)
                        self.tag_beacon_events(beacon, beacon_events)
                        x = 5


class TimelineEnrichment(EnrichmentPlugin):
    def get_timeline_hosts(self):
        query = {
            "size": "0",
            "aggs": {
                "unique_hosts": {
                    "terms": {"field": "target_hostname.keyword"}
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

    def get_reason_lost(self, host):
        result = self.run_query(
            "beacondb",
            f"target_hostname.keyword:{host} AND reason_lost:*")

        if len(result) > 0:
            return result[0]["_source"]["reason_lost"]

        return "C2 Active"

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
                    f'target_hostname.keyword:{host}'
                )

                if len(tmp_host_timeline) == 1:
                    host_timeline = tmp_host_timeline[0]

                assert len(tmp_host_timeline) <= 1
            except NotFoundError:
                pass

            new_beacons = self.run_query(
                "rtops-*",
                f"target_hostname.keyword:{host} AND cslogtype:beacon_newbeacon"
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

                if host_timeline["_source"]["detection_type"] is None or host_timeline["_source"]["detection_type"] == "C2 Active":
                    host_timeline["_source"]["detection_type"] = self.get_reason_lost(
                        host)

                host_timeline["_source"]["start_date"] = new_beacons[0]["_source"]["@timestamp"]
                host_timeline["_source"]["end_date"] = last_checkin[-1]["_source"]["@timestamp"]
                host_timeline["_source"]["days_resident"] = (date_parser.parse(
                    host_timeline["_source"]["end_date"]) - date_parser.parse(host_timeline["_source"]["start_date"])).days

                self.update(host_timeline, index=TIMELINE_INDEX)

            else:
                print(f"Creating new timeline for {host}")
                host_timeline["start_date"] = new_beacons[0]["_source"]["@timestamp"]
                host_timeline["end_date"] = last_checkin[-1]["_source"]["@timestamp"]
                host_timeline["days_resident"] = (date_parser.parse(
                    host_timeline["end_date"]) - date_parser.parse(host_timeline["start_date"])).days
                host_timeline["detection_type"] = self.get_reason_lost(host)
                self.es.index(TIMELINE_INDEX, body=host_timeline)

        for removed_host in removed_hosts:
            self.es.delete_by_query(index=TIMELINE_INDEX, body=self.get_query_json(
                f"target_hostname:{removed_host}"))


class BeaconAtrophyEnrichment(EnrichmentPlugin):
    queue_size = 1

    def run(self):
        for host in self.get_beacondb_hosts():
            last_seen_query = {
                "query": {
                    "bool": {
                        "must": {
                            "match": {
                                "target_hostname.keyword": {
                                    "query": host
                                }
                            }
                        },
                        "must_not": {
                            "exists": {
                                "field": "beacon_input"
                            }
                        }
                    }
                },
                "sort": [
                    {"@timestamp": "desc"}
                ]
            }

            last_interaction_query = {
                "query": {
                    "bool": {
                        "must": {
                            "match": {
                                "target_hostname.keyword": {
                                    "query": host
                                }
                            }
                        },
                        "filter": {
                            "term": {
                                "cslogtype": "beacon_input"
                            }
                        }
                    }
                },
                "sort": [
                    {
                        "@timestamp": "desc"
                    }
                ]
            }

            #query = f"target_hostname.keyword:{host} AND NOT beacon_input:*"
            last_seen = self.run_raw_query(
                "rtops-*", last_seen_query)[0]["_source"]["@timestamp"]

            #query = f"target_hostname.keyword:{host} AND beacon_input:*"
            last_interaction = self.run_raw_query(
                "rtops-*", last_interaction_query)[0]["_source"]
            beacon_atrophy = {
                "target_hostname": host,
                "last_seen": last_seen,
                "last_interaction": last_interaction["@timestamp"],
                "atrophy": (date_parser.parse(last_seen) - date_parser.parse(last_interaction["@timestamp"])).days,
                "last_command": last_interaction["beacon_input"],
                "last_operator": last_interaction["operator"]
            }

            print(beacon_atrophy)

            try:
                existing_rec = self.run_query(
                    "beacon-atrophy", f"target_hostname.keyword:{host}")
            except:
                existing_rec = []

            if len(existing_rec) == 0:
                self.es.index("beacon-atrophy", body=beacon_atrophy)
            else:
                existing_rec[0]["_source"].update(beacon_atrophy)
                self.update(existing_rec[0])
