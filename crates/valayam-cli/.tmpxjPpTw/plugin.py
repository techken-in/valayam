from valayam_sdk import PluginServer, ScannerPlugin, Finding

class .tmpxjPpTwScanner(ScannerPlugin):
def execute(self, template, context):
target = context.get("target_url", "")
return [
Finding(title="Sample Finding", severity="INFO", description=f"Scanned {target}")
]

if __name__ == "__main__":
PluginServer(.tmpxjPpTwScanner()).serve()
