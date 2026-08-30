import subprocess
class WindowsFirewall:
    def __init__(self):
        self.rule_prefix = "AI-FireWall-Block"

    def block_ip(self,ip):
        rule_name = f"{self.rule_prefix}-{ip}"
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name = {rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print(f"FIREWALL BLOCKED IP: {ip}")
            return True
        print(
            "FIREWALL ERROR",
            result.stderr
        )
        return False

    def unblock_ip(self,ip):
        rule_name = f"{self.rule_prefix}-{ip}"
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name = {rule_name}",
        ]
       
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )
       
        if result.returncode == 0:
            print(f"FIREWALL UNBLOCKED IP: {ip}")
            return True
        print(
            "FIREWALL ERROR",
            result.stderr
        )
        return False 