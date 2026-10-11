import copy
import hashlib
import json
import unittest

from maze_headless import analyze
from microfreshener.core.errors import ImporterError
from microfreshener.core.importer import JSONImporter


def envelope(model):
    return {
        "schema_version": 1,
        "evidence_fingerprint": hashlib.sha256(
            json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "model": model,
    }


def graph(target_type="service"):
    return {
        "name": "fixture",
        "nodes": [{"name": "source", "type": "service"}, {"name": "target", "type": target_type}],
        "links": [{"source": "source", "target": "target", "type": "interaction"}],
    }


class MazeHeadlessTests(unittest.TestCase):
    def test_unknown_is_not_false_and_legacy_import_is_unchanged(self):
        model = graph()
        strict = JSONImporter(preserve_unknown=True).Import(json.dumps(model))
        link = strict["source"].interactions[0]
        self.assertIsNone(link.timeout)
        self.assertIsNone(link.circuit_breaker)
        self.assertIsNone(link.dynamic_discovery)
        legacy = JSONImporter().Import(json.dumps(model))
        self.assertIs(legacy["source"].interactions[0].timeout, False)
        result = analyze(envelope(model), ["endpoint-based", "wobbly"])
        self.assertEqual(result["results"]["nodes"], [])
        self.assertEqual(len(result["coverage"]), 2)

    def test_known_false_and_true_resilience(self):
        model = graph()
        model["links"][0].update(timeout=False, circuit_breaker=False, dynamic_discovery=False)
        result = analyze(envelope(model), ["endpoint-based", "wobbly"])
        self.assertEqual(len(result["results"]["nodes"]), 2)
        self.assertEqual(result["coverage"], [])
        model["links"][0].update(timeout=True, circuit_breaker=None, dynamic_discovery=True)
        result = analyze(envelope(model), ["endpoint-based", "wobbly"])
        self.assertEqual(result["results"]["nodes"], [])
        self.assertEqual(result["coverage"], [])

    def test_partial_unknown_still_abstains(self):
        model = graph()
        model["links"][0].update(timeout=False, circuit_breaker=None)
        result = analyze(envelope(model), ["wobbly"])
        self.assertEqual(result["results"]["nodes"], [])
        self.assertEqual(result["coverage"][0]["unknown"], ["circuit_breaker"])

    def test_shared_persistence_uses_upstream_detector_and_refactorings(self):
        model = graph("datastore")
        model["nodes"].append({"name": "other", "type": "service"})
        model["links"].append({"source": "other", "target": "target", "type": "interaction"})
        result = analyze(envelope(model), ["shared-persistency"])
        smell = result["results"]["nodes"][0]["smells"][0]
        self.assertEqual(smell["name"], "Shared-persistency")
        self.assertEqual({link["source"] for link in smell["links"]}, {"source", "other"})
        self.assertEqual(len(smell["refactorings"]), 3)
        self.assertEqual(result["coverage"], [])

    def test_boundary_rejects_forged_identity_invalid_properties_and_detector(self):
        data = envelope(graph())
        altered = copy.deepcopy(data)
        altered["model"]["name"] = "tampered"
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            analyze(altered, ["shared-persistency"])
        altered = graph()
        altered["links"][0]["timeout"] = "false"
        with self.assertRaises(ImporterError):
            analyze(envelope(altered), ["wobbly"])
        for selected in ([], ["shared-persistency", "shared-persistency"], ["unknown"]):
            with self.assertRaises(ValueError):
                analyze(data, selected)


if __name__ == "__main__":
    unittest.main()
