"""Evidence-based provider category rules; unknown is not disposable."""
from .domain_normalizer import normalize_domain

def classify_sender(domain, config, db_match=False):
    rules=config.get("known_provider_rules",{})
    def contains(items):
        normalized=set()
        for x in items or []:
            try: normalized.add(normalize_domain(x))
            except ValueError: pass
        return domain in normalized
    if db_match or contains(rules.get("disposable",[])):
        return {"category":"KNOWN_DISPOSABLE","score":0.85,"status":"OBSERVED","evidence":["Domain matches configured disposable-provider evidence"],"source":"configuration"}
    if contains(rules.get("ordinary",[])):
        return {"category":"ORDINARY_PROVIDER","score":0.05,"status":"OBSERVED","evidence":["Domain matches configured ordinary-provider allowlist"],"source":"configuration"}
    if contains(rules.get("organization",[])):
        return {"category":"ORGANIZATION_OWNED","score":0.05,"status":"OBSERVED","evidence":["Domain matches locally configured organization domains"],"source":"configuration"}
    return {"category":"UNKNOWN","score":None,"status":"UNKNOWN","evidence":["No configured provider classification found"],"source":None}
