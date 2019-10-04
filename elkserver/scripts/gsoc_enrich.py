from enrichment import *

if __name__ == "__main__":
    IOCEnrichment().run()
    BeaconIdTagEnrichment().run()
    KnownSandboxEnrichment().run()
    KnownTestSystemsEnrichment().run()
    ASNEnrichment().run()
    LostAssetEnrichment().run()
    TimelineEnrichment().run()
    BeaconAtrophyEnrichment().run()