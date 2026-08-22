from pymetasploit3.msfrpc import MsfRpcClient


class MSFClient:
    """
    Thin wrapper around the Metasploit RPC connection.
    msfrpcd is running with -S which DISABLES ssl on the socket
    (confirmed via `docker logs msfrpc` -> "MSGRPC starting ... (NO SSL)").
    So ssl=False here to match.

    PERFORMANCE NOTE:
    Scanning all ~2000+ exploit modules for every single CVE lookup is very
    slow (multiple minutes). Instead, build_cve_index() walks every module
    ONCE, and caches cve_id -> [module names]. search_by_cve() then becomes
    an instant dict lookup.
    """

    def __init__(self, password: str, host: str = "localhost", port: int = 55553, use_ssl: bool = False):
        self.client = MsfRpcClient(
            password,
            server=host,
            port=port,
            ssl=use_ssl
        )
        self._cve_index = None  # built lazily on first search_by_cve call

    def list_exploit_modules(self):
        return self.client.modules.exploits

    def build_cve_index(self):
        """
        Walk every exploit module once and build a cve_id -> [module names] map.
        Slow the first time (one full pass over all modules), but only runs once
        per MSFClient instance -- after this, search_by_cve is instant.
        """
        index = {}
        for name in self.client.modules.exploits:
            try:
                mod = self.client.modules.use('exploit', name)
                for ref in mod.references:
                    if ref.upper().startswith("CVE-"):
                        index.setdefault(ref.upper(), []).append(name)
            except Exception:
                # Some modules fail to load metadata (deprecated/broken modules) -- skip them
                continue
        self._cve_index = index
        return index

    def search_by_cve(self, cve_id: str):
        """Return MSF module names referencing the given CVE, using the cached index."""
        if self._cve_index is None:
            self.build_cve_index()
        return self._cve_index.get(cve_id.upper(), [])