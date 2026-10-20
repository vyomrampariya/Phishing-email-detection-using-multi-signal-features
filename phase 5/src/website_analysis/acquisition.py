"""Safe acquisition boundary. Live retrieval intentionally remains disabled."""
class LiveInspectionDisabled(RuntimeError): pass
def inspect_live(url, *args, **kwargs):
    raise LiveInspectionDisabled("Live website fetching is disabled; pass trusted cached evidence or an offline fixture.")
def address_is_public(address):
    """Reject all non-global IPs; useful for a future isolated transport layer."""
    import ipaddress
    try: return ipaddress.ip_address(address).is_global
    except ValueError: return False
def validate_target(url, resolved_addresses):
    from urllib.parse import urlsplit
    p=urlsplit(url)
    if p.scheme not in ("http","https") or not p.hostname: return False
    return bool(resolved_addresses) and all(address_is_public(x) for x in resolved_addresses)
