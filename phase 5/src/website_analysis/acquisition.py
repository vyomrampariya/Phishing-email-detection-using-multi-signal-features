"""Bounded, SSRF-resistant retrieval of static public HTML.

This module never uses a browser, executes page code, follows redirects
automatically, or forwards message data. The socket connects to a validated
numeric address so a later DNS answer cannot change the destination.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import queue
import threading
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

DEFAULTS = {
    "connect_timeout_seconds": 3.0,
    "read_timeout_seconds": 4.0,
    "total_timeout_seconds": 12.0,
    "max_response_bytes": 1_048_576,
    "max_redirects": 4,
}
REDIRECT_CODES = {301, 302, 303, 307, 308}
SENSITIVE_RESPONSE_HEADERS = {"set-cookie", "set-cookie2", "www-authenticate"}
BLOCKED_HOSTS = {
    "localhost", "metadata", "metadata.google.internal", "metadata.azure.internal",
    "metadata.aws.internal", "instance-data.ec2.internal",
}
_DNS_SLOTS = threading.BoundedSemaphore(4)


class UnsafeTarget(ValueError):
    """The URL or one of its resolved destinations violates fetch policy."""


def address_is_public(address: str) -> bool:
    """Accept only globally routable unicast IP addresses."""
    try:
        ip = ipaddress.ip_address(address)
        if getattr(ip, "ipv4_mapped", None) is not None:
            ip = ip.ipv4_mapped
        return bool(ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified))
    except ValueError:
        return False


def _parse_target(url: str):
    if not isinstance(url, str) or not url or any(ord(ch) < 33 or ord(ch) == 127 for ch in url):
        raise UnsafeTarget("URL contains invalid characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UnsafeTarget("URL is malformed") from exc
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".").lower()
    if scheme not in {"http", "https"} or not host:
        raise UnsafeTarget("Only HTTP and HTTPS URLs with a hostname are allowed")
    if parts.username is not None or parts.password is not None:
        raise UnsafeTarget("URLs containing credentials are blocked")
    if "%" in host or host in BLOCKED_HOSTS or host.endswith((".localhost", ".local", ".internal", ".localdomain")):
        raise UnsafeTarget("Local or metadata hostnames are blocked")
    expected_port = 443 if scheme == "https" else 80
    if port is not None and port != expected_port:
        raise UnsafeTarget("Only the standard HTTP and HTTPS ports are allowed")
    port = expected_port
    # Fragments are client-side only and are never sent to the server.
    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    return parts, scheme, host, port, path


def _getaddrinfo_bounded(host: str, port: int, timeout: float):
    """Bound blocking system DNS calls without allowing stalled resolver calls to pile up."""
    if not _DNS_SLOTS.acquire(timeout=max(0.05, timeout)):
        raise TimeoutError("DNS resolver capacity is busy")
    result = queue.Queue(maxsize=1)

    def resolve():
        try:
            result.put((True, socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except Exception as exc:
            result.put((False, exc))
        finally:
            _DNS_SLOTS.release()

    threading.Thread(target=resolve, name="website-dns-lookup", daemon=True).start()
    try:
        ok, value = result.get(timeout=max(0.05, timeout))
    except queue.Empty as exc:
        raise TimeoutError("DNS resolution timed out") from exc
    if not ok:
        raise value
    return value


def resolve_public_addresses(host: str, port: int, timeout: float = 3.0) -> list[str]:
    """Resolve once per hop and reject the whole answer if any IP is unsafe."""
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            records = _getaddrinfo_bounded(host, port, timeout)
        except OSError as exc:
            raise OSError("DNS resolution failed") from exc
        addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise OSError("DNS returned no addresses")
    if not all(address_is_public(address) for address in addresses):
        raise UnsafeTarget("DNS returned a private, reserved, or otherwise non-public address")
    return addresses


def validate_target(url: str, resolved_addresses) -> bool:
    """Compatibility helper retained for Phase 5 callers."""
    try:
        _parts, _scheme, _host, _port, _path = _parse_target(url)
        return bool(resolved_addresses) and all(address_is_public(x) for x in resolved_addresses)
    except (UnsafeTarget, TypeError):
        return False


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self._address = address

    def _open_pinned_socket(self):
        ip = ipaddress.ip_address(self._address)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((str(ip), self.port))
        return sock

    def connect(self):
        self.sock = self._open_pinned_socket()


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    def connect(self):
        raw = self._open_pinned_socket()
        try:
            # The default client context validates both the trust chain and hostname.
            self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _connection(scheme, host, port, address, timeout):
    cls = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
    return cls(host, port, address, timeout)


def _safe_headers(response):
    headers = {}
    total = 0
    for key, value in response.getheaders():
        name = key.lower()
        if name in SENSITIVE_RESPONSE_HEADERS or len(headers) >= 64:
            continue
        # Strip control characters and cap header count, per-value, and total output.
        value = " ".join(str(value).replace("\r", " ").replace("\n", " ").split())[:500]
        if total + len(name) + len(value) > 8192:
            break
        total += len(name) + len(value)
        if name in headers:
            headers[name] = f"{headers[name]}, {value}"[:1000]
        else:
            headers[name] = value
    return headers


def _failure(url, status, reason, *, http_status=None, redirects=None, final_url=None, headers=None):
    return {
        "status": status,
        "original_url": url,
        "redirect_chain": redirects or [],
        "final_url": final_url,
        "http_status": http_status,
        "response_headers": headers or {},
        "reason": reason,
        "fetched": False,
    }


def inspect_live(url: str, config=None, *, resolver=None, connection_factory=None):
    """Fetch at most one bounded HTML page from a safe public HTTP(S) target.

    ``resolver`` and ``connection_factory`` are injected only by offline unit
    tests. Production defaults always use validating DNS and pinned TCP sockets.
    The returned ``html`` is transient input for the static parser; callers must
    remove it before presenting/storing assessment results.
    """
    settings = {**DEFAULTS, **(config or {})}
    for key, low, high in (("connect_timeout_seconds", 0.1, 10.0), ("read_timeout_seconds", 0.1, 10.0), ("total_timeout_seconds", 0.5, 20.0)):
        try:
            settings[key] = min(high, max(low, float(settings[key])))
        except (TypeError, ValueError):
            return _failure(url, "error", f"Invalid {key} configuration")
    try:
        settings["max_response_bytes"] = min(2_097_152, max(1, int(settings["max_response_bytes"])))
        settings["max_redirects"] = min(4, max(0, int(settings["max_redirects"])))
    except (TypeError, ValueError):
        return _failure(url, "error", "Invalid retrieval limits configuration")
    resolver = resolver or resolve_public_addresses
    connection_factory = connection_factory or _connection
    redirects = []
    current = url
    started = time.monotonic()
    deadline = started + float(settings["total_timeout_seconds"])
    max_bytes = settings["max_response_bytes"]
    if max_bytes <= 0:
        return _failure(url, "error", "Invalid response size configuration")
    try:
        for hop in range(int(settings["max_redirects"]) + 1):
            _parts, scheme, host, port, path = _parse_target(current)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("total retrieval deadline exceeded")
            if resolver is resolve_public_addresses:
                addresses = resolver(host, port, min(float(settings["connect_timeout_seconds"]), remaining))
            else:
                addresses = resolver(host, port)
            if not addresses or not all(address_is_public(x) for x in addresses):
                raise UnsafeTarget("DNS returned a private, reserved, or otherwise non-public address")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("total retrieval deadline exceeded")
            timeout = min(float(settings["connect_timeout_seconds"]), remaining)
            conn = connection_factory(scheme, host, port, addresses[0], timeout)
            try:
                conn.request("GET", path, headers={
                    "User-Agent": "VYOM-Static-Phishing-Analyzer/1.0",
                    "Accept": "text/html,application/xhtml+xml;q=0.9",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                })
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("total retrieval deadline exceeded")
                if getattr(conn, "sock", None) is not None:
                    conn.sock.settimeout(min(float(settings["read_timeout_seconds"]), remaining))
                response = conn.getresponse()
                response_headers = _safe_headers(response)
                code = int(response.status)
                if code in REDIRECT_CODES:
                    location = response.getheader("Location")
                    if not location:
                        return _failure(url, "unavailable", "Redirect response had no Location header", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                    if hop >= int(settings["max_redirects"]):
                        return _failure(url, "unavailable", "Redirect limit exceeded", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                    target = urljoin(current, location)
                    redirect_record = {"from": current, "status": code, "to": target[:2048]}
                    # Preserve blocked hops in the chain while ensuring no connection
                    # is made before URL and DNS policy pass.
                    try:
                        _parse_target(target)
                    except UnsafeTarget as exc:
                        redirect_record["blocked"] = True
                        redirects.append(redirect_record)
                        return _failure(url, "unavailable", f"Redirect target blocked: {exc}", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                    redirects.append(redirect_record)
                    current = target
                    continue
                if code != 200:
                    return _failure(url, "unavailable", f"HTTP response status {code}", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
                if content_type not in {"text/html", "application/xhtml+xml"}:
                    return _failure(url, "unavailable", "Response is not HTML", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                if response.getheader("Content-Disposition", "").lower().strip().startswith("attachment"):
                    return _failure(url, "unavailable", "Attachment responses are not opened", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                encoding = (response.getheader("Content-Encoding") or "identity").lower().strip()
                if encoding not in {"", "identity"}:
                    return _failure(url, "unavailable", "Compressed response encoding is not accepted", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                length = response.getheader("Content-Length")
                if length:
                    try:
                        if int(length) > max_bytes:
                            return _failure(url, "unavailable", "Response exceeds the configured byte limit", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                    except ValueError:
                        return _failure(url, "unavailable", "Invalid Content-Length header", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                body = bytearray()
                while len(body) <= max_bytes:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("total retrieval deadline exceeded")
                    if getattr(conn, "sock", None) is not None:
                        conn.sock.settimeout(min(float(settings["read_timeout_seconds"]), remaining))
                    chunk = response.read(min(8192, max_bytes + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                if len(body) > max_bytes:
                    return _failure(url, "unavailable", "Response exceeds the configured byte limit", http_status=code, redirects=redirects, final_url=current, headers=response_headers)
                charset = "utf-8"
                content_type_header = response.getheader("Content-Type") or ""
                for param in content_type_header.split(";")[1:]:
                    key, _, value = param.strip().partition("=")
                    if key.lower() == "charset" and value.strip(" '\""):
                        charset = value.strip(" '\"")[:40]
                        break
                try:
                    html = bytes(body).decode(charset, errors="replace")
                except LookupError:
                    html = bytes(body).decode("utf-8", errors="replace")
                return {
                    "status": "available", "original_url": url, "redirect_chain": redirects,
                    "final_url": current, "http_status": code, "response_headers": response_headers,
                    "reason": None, "fetched": True, "html": html,
                }
            finally:
                conn.close()
        return _failure(url, "unavailable", "Redirect limit exceeded", redirects=redirects, final_url=current)
    except UnsafeTarget as exc:
        return _failure(url, "unavailable", str(exc), redirects=redirects, final_url=current)
    except (TimeoutError, socket.timeout):
        return _failure(url, "unavailable", "Website retrieval timed out", redirects=redirects, final_url=current)
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return _failure(url, "unavailable", "Website retrieval failed due to a network or TLS error", redirects=redirects, final_url=current)
    except Exception as exc:
        return _failure(url, "error", f"Unexpected retrieval error ({type(exc).__name__})", redirects=redirects, final_url=current)

