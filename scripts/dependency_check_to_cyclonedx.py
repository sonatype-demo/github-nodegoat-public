#!/usr/bin/env python3
"""Convert an OWASP Dependency-Check JSON report to CycloneDX 1.6 JSON.

Dependency-Check does not natively emit CycloneDX. This converter preserves the
package identities, hashes, licenses, evidence provenance, and vulnerability
findings present in its JSON report. When package-lock.json is supplied, it is
used only to restore npm dependency relationships and development scope that
Dependency-Check's JSON report does not encode as CycloneDX fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import unquote, urlsplit
import uuid

CYCLONEDX_SPEC_VERSION = "1.6"
TOOL_NAME = "OWASP Dependency-Check report converter"
TOOL_VERSION = "1.0.0"
NAMESPACE = uuid.UUID("fdbb5778-bd9e-5b3b-9168-4b9aa4789198")


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def vulnerability_source_counts(report: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for dependency in report.get("dependencies") or []:
        for vulnerability in dependency.get("vulnerabilities") or []:
            source = str(vulnerability.get("source") or "unknown")
            counts[source] = counts.get(source, 0) + 1
    return counts


def require_vulnerability_source(report: dict[str, Any], expected_source: str) -> None:
    counts = vulnerability_source_counts(report)
    total = sum(counts.values())
    if total == 0:
        raise ValueError(
            f"Expected vulnerabilities from {expected_source}, but the native report contains none"
        )
    unexpected = {source: count for source, count in counts.items() if source != expected_source}
    if unexpected:
        observed = ", ".join(
            f"{source}={count}" for source, count in sorted(counts.items())
        )
        raise ValueError(
            f"Expected all native vulnerabilities to use source {expected_source}; observed {observed}"
        )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def first_purl(dependency: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    for package in dependency.get("packages") or []:
        identifier = package.get("id")
        if isinstance(identifier, str) and identifier.startswith("pkg:"):
            return identifier, package
    return None, None


def parse_purl(purl: str) -> dict[str, str | None]:
    if not purl.startswith("pkg:"):
        raise ValueError(f"Not a Package URL: {purl}")
    without_prefix = purl[4:]
    package_part = without_prefix.split("#", 1)[0].split("?", 1)[0]
    package_type, separator, remainder = package_part.partition("/")
    if not separator or not package_type or not remainder:
        raise ValueError(f"Malformed Package URL: {purl}")
    name_and_namespace, version_separator, version = remainder.rpartition("@")
    if not version_separator:
        name_and_namespace = remainder
        version = None
    decoded_segments = [unquote(part) for part in name_and_namespace.split("/")]
    name = decoded_segments[-1]
    namespace = "/".join(decoded_segments[:-1]) or None
    return {
        "type": unquote(package_type),
        "namespace": namespace,
        "name": name,
        "version": unquote(version) if version is not None else None,
    }


def fallback_ref(dependency: dict[str, Any]) -> str:
    sha256 = dependency.get("sha256")
    if isinstance(sha256, str) and sha256:
        return f"urn:dependency-check:sha256:{sha256.lower()}"
    stable = "\x00".join(
        str(dependency.get(field) or "")
        for field in ("filePath", "fileName", "md5", "sha1")
    )
    return f"urn:uuid:{uuid.uuid5(NAMESPACE, stable)}"


def component_identity(dependency: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    purl, package = first_purl(dependency)
    return (purl or fallback_ref(dependency)), package


def add_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    if item not in items:
        items.append(item)


def add_property(component: dict[str, Any], name: str, value: Any) -> None:
    if value is None or value == "":
        return
    properties = component.setdefault("properties", [])
    add_unique(properties, {"name": name, "value": str(value)})


def dependency_component(dependency: dict[str, Any]) -> dict[str, Any]:
    bom_ref, package = component_identity(dependency)
    purl = bom_ref if bom_ref.startswith("pkg:") else None
    parsed = parse_purl(purl) if purl else None

    component: dict[str, Any] = {
        "type": "library" if purl else "file",
        "bom-ref": bom_ref,
        "name": parsed["name"] if parsed else str(dependency.get("fileName") or "unknown"),
    }
    if parsed:
        if parsed["namespace"]:
            component["group"] = parsed["namespace"]
        if parsed["version"]:
            component["version"] = parsed["version"]
        component["purl"] = purl
    if dependency.get("description"):
        component["description"] = str(dependency["description"])
    if dependency.get("license"):
        component["licenses"] = [
            {"license": {"name": str(dependency["license"])}}
        ]

    hashes = []
    for source_name, algorithm in (
        ("md5", "MD5"),
        ("sha1", "SHA-1"),
        ("sha256", "SHA-256"),
    ):
        content = dependency.get(source_name)
        if isinstance(content, str) and content:
            hashes.append({"alg": algorithm, "content": content.lower()})
    if hashes:
        component["hashes"] = hashes

    if package and package.get("url"):
        component["externalReferences"] = [
            {"type": "distribution", "url": str(package["url"])}
        ]
    if package and package.get("confidence"):
        add_property(component, "dependency-check:packageConfidence", package["confidence"])
    add_property(component, "dependency-check:fileName", dependency.get("fileName"))
    add_property(component, "dependency-check:filePath", dependency.get("filePath"))
    add_property(component, "dependency-check:isVirtual", str(bool(dependency.get("isVirtual"))).lower())

    evidence = dependency.get("evidenceCollected") or {}
    for kind in ("vendorEvidence", "productEvidence", "versionEvidence"):
        values = evidence.get(kind) or []
        if values:
            add_property(
                component,
                f"dependency-check:{kind}",
                json.dumps(values, sort_keys=True, separators=(",", ":")),
            )
    return component


def merge_component(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    for scalar in ("group", "version", "purl", "description"):
        if scalar not in target and scalar in incoming:
            target[scalar] = incoming[scalar]
    for collection in ("hashes", "licenses", "externalReferences", "properties"):
        for item in incoming.get(collection) or []:
            add_unique(target.setdefault(collection, []), item)


def severity_name(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower()
    return {
        "moderate": "medium",
        "negligible": "low",
    }.get(normalized, normalized if normalized in {"unknown", "info", "none", "low", "medium", "high", "critical"} else "unknown")


def vulnerability_score(vulnerability: dict[str, Any]) -> float | int | None:
    for key, score_key in (("cvssv4", "baseScore"), ("cvssv3", "baseScore"), ("cvssv2", "score")):
        value = (vulnerability.get(key) or {}).get(score_key)
        if isinstance(value, (int, float)):
            return value
    return None


def vulnerability_entry(vulnerability: dict[str, Any], bom_ref: str) -> dict[str, Any]:
    source_name = str(vulnerability.get("source") or "OWASP Dependency-Check")
    entry: dict[str, Any] = {
        "id": str(vulnerability.get("name") or "UNKNOWN"),
        "source": {"name": source_name},
        "affects": [{"ref": bom_ref}],
    }
    severity = severity_name(vulnerability.get("severity"))
    rating: dict[str, Any] = {"severity": severity}
    score = vulnerability_score(vulnerability)
    if score is not None:
        rating["score"] = score
    entry["ratings"] = [rating]
    if vulnerability.get("description"):
        entry["description"] = str(vulnerability["description"])
    advisories = []
    for reference in vulnerability.get("references") or []:
        url = reference.get("url")
        if url:
            add_unique(advisories, {"url": str(url)})
    if advisories:
        entry["advisories"] = advisories
    cwes = []
    for cwe in vulnerability.get("cwes") or []:
        match = re.search(r"(\d+)", str(cwe))
        if match:
            value = int(match.group(1))
            if value not in cwes:
                cwes.append(value)
    if cwes:
        entry["cwes"] = cwes
    return entry


def merge_vulnerability(target: dict[str, Any], incoming: dict[str, Any]) -> None:
    for affect in incoming.get("affects") or []:
        add_unique(target.setdefault("affects", []), affect)
    for advisory in incoming.get("advisories") or []:
        add_unique(target.setdefault("advisories", []), advisory)
    for cwe in incoming.get("cwes") or []:
        if cwe not in target.setdefault("cwes", []):
            target["cwes"].append(cwe)


def root_component(report: dict[str, Any], package_json: dict[str, Any] | None) -> dict[str, Any]:
    project = report.get("projectInfo") or {}
    name = (package_json or {}).get("name") or project.get("name") or "dependency-check-project"
    version = (package_json or {}).get("version") or project.get("version")
    component: dict[str, Any] = {
        "type": "application",
        "bom-ref": f"urn:uuid:{uuid.uuid5(NAMESPACE, f'root:{name}:{version or ""}')}",
        "name": str(name),
    }
    if version:
        component["version"] = str(version)
    if package_json and package_json.get("description"):
        component["description"] = str(package_json["description"])
    return component


def npm_name_from_lock_path(path: str, entry: dict[str, Any]) -> str | None:
    explicit = entry.get("name")
    if isinstance(explicit, str) and explicit:
        return explicit
    if not path.startswith("node_modules/"):
        return None
    normalized = path.removeprefix("node_modules/")
    return normalized.rsplit("/node_modules/", 1)[-1]


def resolve_lock_dependency_path(
    parent_path: str,
    dependency_name: str,
    packages: dict[str, Any],
) -> str | None:
    if parent_path:
        if not parent_path.startswith("node_modules/"):
            return None
        chain = parent_path.removeprefix("node_modules/").split("/node_modules/")
    else:
        chain = []
    for depth in range(len(chain), -1, -1):
        candidate_chain = chain[:depth] + [dependency_name]
        candidate = "node_modules/" + "/node_modules/".join(candidate_chain)
        if candidate in packages:
            return candidate
    return None


def npm_dependency_graph(
    package_lock: dict[str, Any],
    component_map: dict[str, dict[str, Any]],
    root_ref: str,
) -> list[dict[str, Any]]:
    packages = package_lock.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("package-lock.json must use lockfileVersion 2 or newer with a packages object")

    coordinate_refs: dict[tuple[str, str], str] = {}
    for component in component_map.values():
        purl = component.get("purl")
        if not isinstance(purl, str):
            continue
        parsed = parse_purl(purl)
        if parsed["type"] != "npm" or not parsed["version"]:
            continue
        full_name = "/".join(
            value for value in (parsed["namespace"], parsed["name"]) if value
        )
        coordinate_refs[(full_name, str(parsed["version"]))] = component["bom-ref"]

    path_refs: dict[str, str] = {}
    scope_rank: dict[str, int] = {}
    scope_names = {0: "excluded", 1: "optional", 2: "required"}
    for path, raw_entry in packages.items():
        if not path or not isinstance(raw_entry, dict):
            continue
        name = npm_name_from_lock_path(path, raw_entry)
        version = raw_entry.get("version")
        if not name or not isinstance(version, str) or not version:
            continue
        bom_ref = coordinate_refs.get((name, version))
        if not bom_ref:
            continue
        path_refs[path] = bom_ref
        rank = 0 if raw_entry.get("dev") is True else 1 if raw_entry.get("optional") is True else 2
        scope_rank[bom_ref] = max(scope_rank.get(bom_ref, -1), rank)

    for bom_ref, rank in scope_rank.items():
        component_map[bom_ref]["scope"] = scope_names[rank]

    graph: dict[str, set[str]] = {root_ref: set()}
    for bom_ref in path_refs.values():
        graph.setdefault(bom_ref, set())

    for path, raw_entry in packages.items():
        if not isinstance(raw_entry, dict):
            continue
        source_ref = root_ref if path == "" else path_refs.get(path)
        if not source_ref:
            continue
        dependency_names: set[str] = set()
        fields = ["dependencies", "optionalDependencies", "peerDependencies"]
        if path == "":
            fields.append("devDependencies")
        for field in fields:
            values = raw_entry.get(field)
            if isinstance(values, dict):
                dependency_names.update(str(name) for name in values)
        for dependency_name in dependency_names:
            resolved_path = resolve_lock_dependency_path(path, dependency_name, packages)
            if resolved_path and resolved_path in path_refs:
                graph.setdefault(source_ref, set()).add(path_refs[resolved_path])

    ordered_refs = [root_ref] + sorted(ref for ref in graph if ref != root_ref)
    return [
        {"ref": ref, "dependsOn": sorted(graph.get(ref, set()))}
        for ref in ordered_refs
    ]


def build_bom(
    report: dict[str, Any],
    package_json: dict[str, Any] | None = None,
    package_lock: dict[str, Any] | None = None,
    label: str | None = None,
    vulnerability_provider: str | None = None,
) -> dict[str, Any]:
    dependencies = report.get("dependencies")
    if not isinstance(dependencies, list):
        raise ValueError("Dependency-Check report has no dependencies array")

    component_map: dict[str, dict[str, Any]] = {}
    vulnerability_map: dict[tuple[str, str], dict[str, Any]] = {}
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        component = dependency_component(dependency)
        bom_ref = component["bom-ref"]
        if bom_ref in component_map:
            merge_component(component_map[bom_ref], component)
        else:
            component_map[bom_ref] = component
        for vulnerability in dependency.get("vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            key = (
                str(vulnerability.get("source") or "OWASP Dependency-Check"),
                str(vulnerability.get("name") or "UNKNOWN"),
            )
            incoming = vulnerability_entry(vulnerability, bom_ref)
            if key in vulnerability_map:
                merge_vulnerability(vulnerability_map[key], incoming)
            else:
                vulnerability_map[key] = incoming

    root = root_component(report, package_json)
    dependency_graph = (
        npm_dependency_graph(package_lock, component_map, root["bom-ref"])
        if package_lock is not None
        else [{"ref": root["bom-ref"], "dependsOn": []}]
    )
    components = sorted(
        component_map.values(),
        key=lambda item: (str(item.get("purl") or ""), str(item["bom-ref"])),
    )
    vulnerabilities = sorted(
        vulnerability_map.values(),
        key=lambda item: (str((item.get("source") or {}).get("name") or ""), str(item["id"])),
    )
    report_digest = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    timestamp = (report.get("projectInfo") or {}).get("reportDate")
    engine_version = (report.get("scanInfo") or {}).get("engineVersion")

    metadata: dict[str, Any] = {
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "OWASP Dependency-Check",
                    **({"version": str(engine_version)} if engine_version else {}),
                    "externalReferences": [
                        {
                            "type": "website",
                            "url": "https://github.com/dependency-check/DependencyCheck",
                        }
                    ],
                },
                {
                    "type": "application",
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                },
            ]
        },
        "component": root,
        "properties": [
            {"name": "dependency-check:reportSchema", "value": str(report.get("reportSchema") or "unknown")},
            {"name": "dependency-check:reportSha256", "value": report_digest},
            {
                "name": "dependency-check:dependencyGraphSource",
                "value": "package-lock.json" if package_lock is not None else "not-provided",
            },
        ],
    }
    if label:
        metadata["properties"].append(
            {"name": "sonatype:sbomLabel", "value": label}
        )
    if vulnerability_provider:
        metadata["properties"].append(
            {
                "name": "dependency-check:vulnerabilityProvider",
                "value": vulnerability_provider,
            }
        )
    if timestamp:
        metadata["timestamp"] = str(timestamp)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(NAMESPACE, report_digest)}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependency_graph,
    }
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    validate_bom(bom)
    return bom


def validate_bom(bom: dict[str, Any]) -> None:
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != CYCLONEDX_SPEC_VERSION:
        raise ValueError("Output is not CycloneDX 1.6")
    components = bom.get("components") or []
    refs = [component.get("bom-ref") for component in components]
    if any(not ref for ref in refs) or len(refs) != len(set(refs)):
        raise ValueError("Component bom-ref values must be present and unique")
    known_refs = set(refs)
    root_ref = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if not root_ref:
        raise ValueError("Metadata component must have a bom-ref")
    known_refs.add(root_ref)
    for dependency in bom.get("dependencies") or []:
        if dependency.get("ref") not in known_refs:
            raise ValueError(f"Unknown dependency ref: {dependency.get('ref')}")
        for affected in dependency.get("dependsOn") or []:
            if affected not in known_refs:
                raise ValueError(f"Unknown dependsOn ref: {affected}")
    for vulnerability in bom.get("vulnerabilities") or []:
        for affect in vulnerability.get("affects") or []:
            if affect.get("ref") not in known_refs:
                raise ValueError(f"Unknown vulnerability ref: {affect.get('ref')}")


def markdown_summary(
    report: dict[str, Any],
    bom: dict[str, Any],
    label: str | None = None,
    vulnerability_provider: str | None = None,
) -> str:
    raw_dependencies = report.get("dependencies") or []
    virtual_dependencies = sum(1 for item in raw_dependencies if item.get("isVirtual"))
    components = bom.get("components") or []
    vulnerabilities = bom.get("vulnerabilities") or []
    graph = bom.get("dependencies") or []
    graph_edges = sum(len(item.get("dependsOn") or []) for item in graph)
    scopes = {
        scope: sum(1 for component in components if component.get("scope") == scope)
        for scope in ("required", "optional", "excluded")
    }
    engine_version = (report.get("scanInfo") or {}).get("engineVersion") or "unknown"
    source_counts = vulnerability_source_counts(report)
    source_summary = ", ".join(
        f"{source}={count}" for source, count in sorted(source_counts.items())
    ) or "none"
    title = (
        f"# {label} — Dependency-Check-derived CycloneDX SBOM"
        if label
        else "# OWASP Dependency-Check-derived CycloneDX SBOM"
    )
    profile_lines = []
    if label:
        profile_lines.append(f"- SBOM label: **{label}**")
    if vulnerability_provider:
        profile_lines.append(
            f"- Configured vulnerability provider: **{vulnerability_provider}**"
        )
    return "\n".join(
        [
            title,
            "",
            "> OWASP Dependency-Check does not natively emit CycloneDX. This workflow converts its JSON report into a CycloneDX 1.6 document, restores npm graph/scope data from package-lock.json, and retains the original report alongside it.",
            "",
            *profile_lines,
            f"- Dependency-Check version: `{engine_version}`",
            f"- Dependency-Check report entries: **{len(raw_dependencies)}**",
            f"- Virtual Dependency-Check entries: **{virtual_dependencies}**",
            f"- Native vulnerability sources: **{source_summary}**",
            f"- Unique CycloneDX components: **{len(components)}**",
            f"- Dependency graph nodes / edges: **{len(graph)} / {graph_edges}**",
            f"- Component scope required / optional / excluded: **{scopes['required']} / {scopes['optional']} / {scopes['excluded']}**",
            f"- CycloneDX vulnerability records: **{len(vulnerabilities)}**",
            "- Output validation: structural CycloneDX 1.6 checks passed",
            "",
        ]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True, help="Dependency-Check JSON report")
    parser.add_argument("--output", type=Path, required=True, help="CycloneDX 1.6 JSON output")
    parser.add_argument("--package-json", type=Path, help="Optional package.json for root component metadata")
    parser.add_argument(
        "--package-lock",
        type=Path,
        help="Optional package-lock.json for npm graph and component scope",
    )
    parser.add_argument("--label", help="Optional SBOM profile label stored in CycloneDX metadata")
    parser.add_argument(
        "--vulnerability-provider",
        help="Optional configured vulnerability-provider description stored in metadata",
    )
    parser.add_argument(
        "--require-vulnerability-source",
        help="Fail unless the native report has vulnerabilities and every finding uses this source",
    )
    parser.add_argument("--summary-output", type=Path, help="Optional Markdown summary output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = load_json(args.input)
    if args.require_vulnerability_source:
        require_vulnerability_source(report, args.require_vulnerability_source)
    package_json = load_json(args.package_json) if args.package_json else None
    package_lock = load_json(args.package_lock) if args.package_lock else None
    bom = build_bom(
        report,
        package_json,
        package_lock,
        label=args.label,
        vulnerability_provider=args.vulnerability_provider,
    )
    write_json(args.output, bom)
    if args.summary_output:
        args.summary_output.parent.mkdir(parents=True, exist_ok=True)
        args.summary_output.write_text(
            markdown_summary(
                report,
                bom,
                label=args.label,
                vulnerability_provider=args.vulnerability_provider,
            ),
            encoding="utf-8",
        )
    print(
        json.dumps(
            {
                "dependencyCheckEntries": len(report.get("dependencies") or []),
                "cycloneDxComponents": len(bom.get("components") or []),
                "cycloneDxVulnerabilities": len(bom.get("vulnerabilities") or []),
                "label": args.label,
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
