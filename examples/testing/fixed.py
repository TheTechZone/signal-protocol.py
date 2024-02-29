import test
from mitmproxy import http
import sys

def _v3_keys_ids(flow: http.HTTPFlow, ids: str):
    return ids + "v3"


sys.modules[test.__name__]._v2_keys_ids = _v3_keys_ids

print(test._v2_keys_ids(None, "test"))  # testv3
