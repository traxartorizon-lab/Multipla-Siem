"""Deterministic CycloneDX inventory of locked Windows NuGet dependencies.

Self-contained .NET runtime files are additionally covered by the signed exact
Windows manifest and the pinned SDK provenance; this inventory makes no claim
to have discovered transitive native OS components or vulnerability absence.
"""
import base64
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
lock = json.loads((root / "desktop/packages.lock.json").read_text(encoding="utf-8"))
packages = {}
for framework in lock["dependencies"].values():
    for name, package in framework.items():
        if package.get("type") == "Project":
            continue
        identity = name, package["resolved"]
        previous = packages.setdefault(identity, package)
        assert previous["contentHash"] == package["contentHash"], identity
components = []
dependencies = []
for (name, version), package in sorted(packages.items()):
    purl = f"pkg:nuget/{name}@{version}"
    assert len(base64.b64decode(package["contentHash"], validate=True)) == 64
    component = {"type": "library", "name": name, "version": version,
                 "bom-ref": purl, "purl": purl,
                 "properties": [{"name": "nuget:contentHash:SHA-512:base64", "value": package["contentHash"]},
                                {"name": "nuget:contentHash:scope", "value": "NuGet normalized package content hash from packages.lock.json; not the raw .nupkg file checksum"}]}
    if name == "BouncyCastle.Cryptography":
        component["licenses"] = [{"license": {"id": "MIT"}}, {"license": {"id": "Apache-2.0"}}]
    components.append(component)
    dependencies.append({"ref": purl, "dependsOn": [f"pkg:nuget/{dep}@{ver}" for dep, ver in sorted(package.get("dependencies", {}).items())]})
version = (root / "VERSION").read_text().strip()
application = f"Multipla-SIEM-Windows@{version}"
dependencies.append({"ref": application, "dependsOn": [item["bom-ref"] for item in components]})
document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "Multipla SIEM Windows", "version": version, "bom-ref": application},
                         "properties": [{"name": "multipla:inventory-scope", "value": "Locked NuGet dependencies; .NET runtime covered by signed Windows file manifest and pinned SDK provenance"}]},
            "components": components, "dependencies": dependencies}
destination = root / "desktop/windows-nuget-sbom.cdx.json"
destination.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
print(f"Windows NuGet SBOM: {len(components)} locked components")
