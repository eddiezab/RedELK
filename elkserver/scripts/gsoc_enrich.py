from enrichment import *

if __name__ == "__main__":
    BeaconIdTagEnrichment().run()
    KnownSandboxEnrichment().run()
    ASNEnrichment().run()
    LostAssetEnrichment().run()
    TimelineEnrichment().run()
    BeaconAtrophyEnrichment().run()