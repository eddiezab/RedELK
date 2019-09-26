from enrichment import *

def pprint(r):
    print(json.dumps(r, indent=2, sort_keys=True))

if __name__ == "__main__":
    for plugin in [ASNEnrichmentPlugin]:
        pprint(plugin().run())