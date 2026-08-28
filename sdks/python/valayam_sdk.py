import json

class ValayamSDK:
    def __init__(self, host_bridge):
        """
        Initialize the SDK with a host bridge that implements 
        get_kv, set_kv, and resolve_dns methods.
        """
        self.host_bridge = host_bridge

    def get_kv(self, key: str) -> str:
        return self.host_bridge.get_kv(key)

    def set_kv(self, key: str, value: str):
        self.host_bridge.set_kv(key, value)

    def resolve_dns(self, domain: str) -> list[str]:
        return self.host_bridge.resolve_dns(domain)

    def report_finding(self, name: str, description: str):
        finding = {
            "name": name,
            "description": description
        }
        # In a real environment, this would call a specific host function
        # to submit the finding back to the valayam engine
        raise NotImplementedError("report_finding is not fully implemented")
