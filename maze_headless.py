"""Run selected upstream detectors on a URL-free MAZE evidence model."""

import argparse
import hashlib
import json
import os
from pathlib import Path

os.environ["MAZE_MICROFRESHENER_HEADLESS"] = "1"

from microfreshener.core.analyser import MicroToscaAnalyserBuilder  # noqa: E402
from microfreshener.core.importer import JSONImporter  # noqa: E402

DETECTORS = {
    "shared-persistency": 6,
    "endpoint-based": 3,
    "wobbly": 4,
}
PROPERTIES = {
    "endpoint-based": ("dynamic_discovery",),
    "wobbly": ("timeout", "circuit_breaker"),
    "shared-persistency": (),
}


def analyze(data, detectors):
    if (
        set(data) != {"schema_version", "evidence_fingerprint", "model"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] not in (1, 2)
    ):
        raise ValueError("Unsupported evidence envelope")
    version = data["schema_version"]
    identity = data["evidence_fingerprint"]
    if (
        not isinstance(identity, str)
        or len(identity) != 64
        or any(c not in "0123456789abcdef" for c in identity)
    ):
        raise ValueError("Invalid evidence identity")
    graph = data["model"]
    if (
        hashlib.sha256(
            json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        != identity
    ):
        raise ValueError("Evidence fingerprint differs from model")
    if set(graph) != {"name", "nodes", "links"} or not isinstance(graph["name"], str):
        raise ValueError("Invalid model")
    nodes = graph["nodes"]
    if not isinstance(nodes, list) or any(
        set(n) != {"name", "type"}
        or n["type"] not in {"service", "datastore"}
        or not isinstance(n["name"], str)
        or not n["name"]
        for n in nodes
    ):
        raise ValueError("Invalid model nodes")
    names = {n["name"]: n["type"] for n in nodes}
    if len(names) != len(nodes):
        raise ValueError("Duplicate model nodes")
    links = graph["links"]
    if not isinstance(links, list):
        raise ValueError("Invalid model links")
    seen = set()
    for link in links:
        if not {"source", "target", "type"} <= set(link) or set(link) - {
            "source",
            "target",
            "type",
            "timeout",
            "circuit_breaker",
            "dynamic_discovery",
            *({"evidence_id"} if version == 2 else set()),
        }:
            raise ValueError("Invalid interaction")
        pair = link["source"], link["target"]
        identifier = link.get("evidence_id") if version == 2 else pair
        if version == 2 and (not isinstance(identifier, str) or not identifier or len(identifier) > 128):
            raise ValueError("Invalid interaction evidence ID")
        if (
            names.get(pair[0]) != "service"
            or pair[1] not in names
            or pair[0] == pair[1]
            or identifier in seen
            or link["type"] != "interaction"
        ):
            raise ValueError("Invalid interaction ownership")
        seen.add(identifier)
    if (
        not detectors
        or len(set(detectors)) != len(detectors)
        or any(d not in DETECTORS for d in detectors)
    ):
        raise ValueError("Select supported detectors explicitly")
    model = JSONImporter(preserve_unknown=True).Import(json.dumps(graph))
    builder = MicroToscaAnalyserBuilder(model)
    coverage = []
    for detector in detectors:
        builder.add_smell(DETECTORS[detector])
        for link in links:
            if names[link["target"]] != "service":
                continue
            missing = [key for key in PROPERTIES[detector] if link.get(key) is None]
            # One known guard prevents a wobbly finding even if the other is unknown.
            if detector == "wobbly" and any(link.get(key) is True for key in PROPERTIES[detector]):
                missing = []
            if missing:
                coverage.append(
                    {
                        "detector": detector,
                        "source": link["source"],
                        "target": link["target"],
                        "unknown": missing,
                        **({"evidence_id": link["evidence_id"]} if version == 2 else {}),
                    }
                )
    return {
        "schema_version": version,
        "evidence_fingerprint": identity,
        "detectors": detectors,
        "results": builder.build().run(),
        "coverage": coverage,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--detector", required=True, action="append", choices=DETECTORS)
    args = parser.parse_args()
    data = json.loads(args.input.read_text())
    print(json.dumps(analyze(data, args.detector), sort_keys=True))


if __name__ == "__main__":
    main()
