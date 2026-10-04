#!/usr/bin/env python3
"""Compare two CycloneDX JSON SBOMs without external dependencies."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, unquote

Component = dict[str, Any]
IdentityFunction = Callable[[Component], str | None]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare CycloneDX component coverage and metadata."
    )
    parser.add_argument("--dependency-track", required=True, type=Path)
    parser.add_argument("--lifecycle", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    parser.add_argument("--sample-size", type=int, default=25)
    return parser.parse_args()


def load_bom(path: Path) -> dict[str, Any]:
    with path.open("rb") as raw_handle:
        is_gzip = raw_handle.read(2) == b"\x1f\x8b"
    open_document = gzip.open if is_gzip else Path.open
    with open_document(path, mode="rt", encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path} is not a CycloneDX document")
    if not isinstance(document.get("components", []), list):
        raise ValueError(f"{path} has no valid components array")
    return document


def canonical_purl(purl: str, include_qualifiers: bool) -> str:
    base_and_qualifiers, subpath_separator, subpath = purl.partition("#")
    base, qualifier_separator, qualifiers = base_and_qualifiers.partition("?")
    result = unquote(base)

    if include_qualifiers and qualifier_separator:
        normalized_qualifiers = sorted(
            (unquote(key), unquote(value))
            for key, value in parse_qsl(qualifiers, keep_blank_values=True)
        )
        result += "?" + "&".join(
            f"{key}={value}" for key, value in normalized_qualifiers
        )
    if include_qualifiers and subpath_separator:
        result += f"#{unquote(subpath)}"
    return result


def fallback_identity(component: Component) -> str | None:
    name = component.get("name")
    version = component.get("version")
    if not name or not version:
        return None
    group = component.get("group")
    qualified_name = f"{group}/{name}" if group else str(name)
    return f"name:{qualified_name}@{version}"


def strict_identity(component: Component) -> str | None:
    purl = component.get("purl")
    if isinstance(purl, str) and purl:
        return canonical_purl(purl, include_qualifiers=True)
    return fallback_identity(component)


def coordinate_identity(component: Component) -> str | None:
    purl = component.get("purl")
    if isinstance(purl, str) and purl:
        return canonical_purl(purl, include_qualifiers=False)
    return fallback_identity(component)


def dependency_edge_count(document: dict[str, Any]) -> int:
    return sum(
        len(entry.get("dependsOn", []))
        for entry in document.get("dependencies", [])
        if isinstance(entry, dict)
    )


def coverage_count(components: list[Component], field: str) -> int:
    return sum(bool(component.get(field)) for component in components)


def identity_counts(
    components: list[Component], identity_function: IdentityFunction
) -> Counter[str]:
    return Counter(
        identity
        for component in components
        if (identity := identity_function(component)) is not None
    )


def summarize(document: dict[str, Any]) -> dict[str, Any]:
    components = [
        component
        for component in document.get("components", [])
        if isinstance(component, dict)
    ]
    coordinate_counts = identity_counts(components, coordinate_identity)
    strict_counts = identity_counts(components, strict_identity)
    vulnerabilities = document.get("vulnerabilities", [])

    return {
        "cyclonedx_spec_version": document.get("specVersion"),
        "component_entries": len(components),
        "unique_component_coordinates": len(coordinate_counts),
        "unique_strict_identities": len(strict_counts),
        "duplicate_coordinate_entries": sum(
            count - 1 for count in coordinate_counts.values() if count > 1
        ),
        "components_with_purl": coverage_count(components, "purl"),
        "components_with_licenses": coverage_count(components, "licenses"),
        "components_with_hashes": coverage_count(components, "hashes"),
        "components_with_evidence": coverage_count(components, "evidence"),
        "components_with_external_references": coverage_count(
            components, "externalReferences"
        ),
        "dependency_nodes": len(document.get("dependencies", [])),
        "dependency_edges": dependency_edge_count(document),
        "vulnerability_entries": len(vulnerabilities)
        if isinstance(vulnerabilities, list)
        else 0,
    }


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def metadata_by_coordinate(
    document: dict[str, Any],
) -> dict[str, dict[str, set[str]]]:
    metadata: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {
            "licenses": set(),
            "hashes": set(),
            "externalReferences": set(),
            "evidence": set(),
        }
    )
    for component in document.get("components", []):
        if not isinstance(component, dict):
            continue
        identity = coordinate_identity(component)
        if identity is None:
            continue
        metadata[identity]
        for field in ("licenses", "hashes", "externalReferences"):
            value = component.get(field)
            if isinstance(value, list):
                metadata[identity][field].update(canonical_json(item) for item in value)
        evidence = component.get("evidence")
        if evidence:
            digest = hashlib.sha256(canonical_json(evidence).encode("utf-8")).hexdigest()
            metadata[identity]["evidence"].add(digest)
    return metadata


def decode_canonical_values(field: str, values: set[str]) -> list[Any]:
    if field == "evidence":
        return sorted(values)
    return [json.loads(value) for value in sorted(values)]


def compare_metadata_values(
    dependency_track_bom: dict[str, Any], lifecycle_bom: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    dependency_track_metadata = metadata_by_coordinate(dependency_track_bom)
    lifecycle_metadata = metadata_by_coordinate(lifecycle_bom)
    shared = sorted(set(dependency_track_metadata) & set(lifecycle_metadata))
    result: dict[str, dict[str, Any]] = {}

    for field in ("licenses", "hashes", "externalReferences", "evidence"):
        differences = []
        for identity in shared:
            dependency_track_values = dependency_track_metadata[identity][field]
            lifecycle_values = lifecycle_metadata[identity][field]
            if dependency_track_values == lifecycle_values:
                continue
            differences.append(
                {
                    "component": identity,
                    "dependency_track_input": decode_canonical_values(
                        field, dependency_track_values
                    ),
                    "lifecycle": decode_canonical_values(field, lifecycle_values),
                }
            )
        result[field] = {
            "different_shared_components": len(differences),
            "differences": differences,
        }
    return result


def components(document: dict[str, Any]) -> list[Component]:
    return [
        component
        for component in document.get("components", [])
        if isinstance(component, dict)
    ]


def compare_identities(
    dependency_track_bom: dict[str, Any],
    lifecycle_bom: dict[str, Any],
    identity_function: IdentityFunction,
) -> tuple[dict[str, Any], list[str], list[str]]:
    dependency_track_components = set(
        identity_counts(components(dependency_track_bom), identity_function)
    )
    lifecycle_components = set(
        identity_counts(components(lifecycle_bom), identity_function)
    )
    shared = dependency_track_components & lifecycle_components
    dependency_track_only = sorted(dependency_track_components - lifecycle_components)
    lifecycle_only = sorted(lifecycle_components - dependency_track_components)
    union = dependency_track_components | lifecycle_components
    summary = {
        "shared": len(shared),
        "dependency_track_only": len(dependency_track_only),
        "lifecycle_only": len(lifecycle_only),
        "jaccard_similarity": round(len(shared) / len(union), 6)
        if union
        else 1.0,
    }
    return summary, dependency_track_only, lifecycle_only


def markdown_table(dependency_track: dict[str, Any], lifecycle: dict[str, Any]) -> str:
    labels = [
        ("CycloneDX spec", "cyclonedx_spec_version"),
        ("Component entries", "component_entries"),
        ("Unique component coordinates", "unique_component_coordinates"),
        ("Unique strict identities", "unique_strict_identities"),
        ("Duplicate coordinate entries", "duplicate_coordinate_entries"),
        ("Components with PURL", "components_with_purl"),
        ("Components with licenses", "components_with_licenses"),
        ("Components with hashes", "components_with_hashes"),
        ("Components with evidence", "components_with_evidence"),
        (
            "Components with external references",
            "components_with_external_references",
        ),
        ("Dependency graph nodes", "dependency_nodes"),
        ("Dependency graph edges", "dependency_edges"),
        ("Vulnerability entries", "vulnerability_entries"),
    ]
    rows = [
        "| Metric | CycloneDX npm / Dependency-Track input | Lifecycle |",
        "|---|---:|---:|",
    ]
    rows.extend(
        f"| {label} | {dependency_track[key]} | {lifecycle[key]} |"
        for label, key in labels
    )
    return "\n".join(rows)


def overlap_table(
    coordinate_overlap: dict[str, Any], strict_overlap: dict[str, Any]
) -> str:
    rows = [
        "| Match mode | Shared | Dependency-Track input only | Lifecycle only | Jaccard |",
        "|---|---:|---:|---:|---:|",
    ]
    for label, values in (
        ("Coordinate (qualifiers/subpath removed)", coordinate_overlap),
        ("Strict PURL", strict_overlap),
    ):
        rows.append(
            f"| {label} | {values['shared']} | {values['dependency_track_only']} | "
            f"{values['lifecycle_only']} | {values['jaccard_similarity']:.2%} |"
        )
    return "\n".join(rows)


def metadata_table(metadata_differences: dict[str, dict[str, Any]]) -> str:
    labels = {
        "licenses": "License values",
        "hashes": "Hash values",
        "externalReferences": "External-reference values",
        "evidence": "Evidence values (SHA-256 fingerprints)",
    }
    rows = [
        "| Metadata field | Shared components with different values |",
        "|---|---:|",
    ]
    rows.extend(
        f"| {labels[field]} | {values['different_shared_components']} |"
        for field, values in metadata_differences.items()
    )
    return "\n".join(rows)


def bullet_sample(values: list[str], sample_size: int) -> str:
    if not values:
        return "- _None_"
    lines = [f"- `{value}`" for value in values[:sample_size]]
    remaining = len(values) - sample_size
    if remaining > 0:
        lines.append(f"- _...and {remaining} more in the JSON report_")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    dependency_track_bom = load_bom(args.dependency_track)
    lifecycle_bom = load_bom(args.lifecycle)

    dependency_track_summary = summarize(dependency_track_bom)
    lifecycle_summary = summarize(lifecycle_bom)
    coordinate_overlap, dependency_track_only, lifecycle_only = compare_identities(
        dependency_track_bom, lifecycle_bom, coordinate_identity
    )
    strict_overlap, strict_dependency_track_only, strict_lifecycle_only = (
        compare_identities(dependency_track_bom, lifecycle_bom, strict_identity)
    )
    metadata_differences = compare_metadata_values(
        dependency_track_bom, lifecycle_bom
    )

    comparison = {
        "normalization": {
            "coordinate": "URL-decoded PURL without qualifiers or subpath; version case is preserved",
            "strict": "URL-decoded PURL with sorted qualifiers and subpath; version case is preserved",
            "fallback": "group/name@version when PURL is absent",
        },
        "dependency_track_input": dependency_track_summary,
        "lifecycle": lifecycle_summary,
        "coordinate_overlap": coordinate_overlap,
        "strict_identity_overlap": strict_overlap,
        "dependency_track_only_coordinates": dependency_track_only,
        "lifecycle_only_coordinates": lifecycle_only,
        "dependency_track_only_strict_identities": strict_dependency_track_only,
        "lifecycle_only_strict_identities": strict_lifecycle_only,
        "metadata_value_differences": metadata_differences,
    }

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    markdown = f"""# CycloneDX SBOM comparison

Dependency-Track consumes CycloneDX SBOMs; it does not create the npm inventory itself. This comparison uses the official CycloneDX npm generator as the Dependency-Track input and compares it with the CycloneDX SBOM exported by Sonatype Lifecycle for the same installed project tree.

## Inventory and metadata coverage

{markdown_table(dependency_track_summary, lifecycle_summary)}

## Component overlap

{overlap_table(coordinate_overlap, strict_overlap)}

Coordinate matching intentionally ignores PURL qualifiers and subpaths to compare package inventory. Strict matching retains them so source or provenance differences remain visible. Neither mode case-folds versions.

## Metadata value differences

{metadata_table(metadata_differences)}

The JSON report contains the differing license, hash, external-reference, and evidence values for every shared component. Evidence objects are represented by SHA-256 fingerprints to keep the report bounded; the original SBOMs contain the full evidence.

### CycloneDX npm / Dependency-Track input-only coordinates

{bullet_sample(dependency_track_only, args.sample_size)}

### Lifecycle-only coordinates

{bullet_sample(lifecycle_only, args.sample_size)}

> Differences are expected: generators can use different evidence sources, bundled-package handling, deduplication, and enrichment. Review the full JSON report and both original SBOMs before drawing conclusions.
"""
    args.markdown_output.write_text(markdown, encoding="utf-8")
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
