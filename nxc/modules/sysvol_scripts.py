from io import BytesIO
from nxc.helpers.misc import CATEGORY

SCRIPT_EXTENSIONS = [".bat", ".cmd", ".ps1", ".vbs", ".wsf"]

SENSITIVE_PATTERNS = [
    "password",
    "passwd",
    "passw",
    " pass ",
    "pwd=",
    "pwd =",
    "-password",
    "convertto-securestring",
    "get-credential",
    "net use",
    "runas /user",
    "set-adaccountpassword",
    "set-localuser",
    "new-localuser",
    "authorization: basic",
    "token=",
    "apikey",
    "api_key",
    "secret",
]


class NXCModule:
    """
    Module by @harouna
    Spiders SYSVOL for logon/startup scripts (.bat, .cmd, .ps1, .vbs, .wsf)
    and greps each file for credential patterns.
    """

    name = "sysvol_scripts"
    description = "Searches SYSVOL scripts for hardcoded credentials and sensitive commands"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        EXTENSIONS  Comma-separated list of extensions to look for (default: .bat,.cmd,.ps1,.vbs,.wsf)
        SAVE        Directory path to save matching script files locally
        ALL         Show all scripts even without findings (default: False)
        """
        extensions = module_options.get("EXTENSIONS", "")
        self.extensions = [e.strip() for e in extensions.split(",")] if extensions else SCRIPT_EXTENSIONS
        self.save_dir = module_options.get("SAVE", "")
        self.show_all = module_options.get("ALL", "").lower() in ("true", "1", "yes")

    def on_login(self, context, connection):
        try:
            connection.conn.listPath("SYSVOL", "*")
        except Exception as e:
            context.log.fail(f"Cannot access SYSVOL: {e}")
            return

        context.log.display("Searching for script files in SYSVOL...")
        paths = connection.spider("SYSVOL", pattern=self.extensions)

        if not paths:
            context.log.display("No script files found in SYSVOL")
            return

        context.log.success(f"{len(paths)} script file(s) found")

        hits = 0
        for path in paths:
            buf = BytesIO()
            try:
                connection.conn.getFile("SYSVOL", path, buf.write)
            except Exception as e:
                context.log.fail(f"Could not read {path}: {e}")
                continue

            content = buf.getvalue().decode("utf-8", errors="ignore")
            matches = self._grep(content)

            if not matches and not self.show_all:
                continue

            hits += 1
            context.log.success(f"{path}")

            for lineno, line, pattern in matches:
                context.log.highlight(f"  line {lineno:<4} [{pattern}]  {line.strip()}")

            if self.save_dir:
                self._save_file(context, path, buf.getvalue())

        if hits == 0:
            context.log.display("No sensitive patterns found in script files")

    def _grep(self, content: str) -> list:
        results = []
        for lineno, line in enumerate(content.splitlines(), start=1):
            line_lower = line.lower()
            for pattern in SENSITIVE_PATTERNS:
                if pattern in line_lower:
                    results.append((lineno, line, pattern))
                    break
        return results

    def _save_file(self, context, remote_path: str, data: bytes) -> None:
        import os
        safe_name = remote_path.replace("\\", "_").replace("/", "_").lstrip("_")
        local_path = os.path.join(self.save_dir, safe_name)
        try:
            os.makedirs(self.save_dir, exist_ok=True)
            with open(local_path, "wb") as fh:
                fh.write(data)
            context.log.success(f"Saved -> {local_path}")
        except Exception as e:
            context.log.fail(f"Could not save {remote_path}: {e}")
