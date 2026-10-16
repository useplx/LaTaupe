from __future__ import annotations

import json
import math
import random
from pathlib import Path
from zipfile import ZipFile

import ijson
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from app.features import Request, extract

FEATURES = list(extract(Request("GET", "/", {})).mapping())


def literal(value: float) -> str:
    literal = f"{float(value):.9g}"
    if "." not in literal and "e" not in literal.lower():
        literal += ".0"
    return literal + "f"


def records(archive_path: str | Path, label: int, maximum: int | None,
            random_state: int, max_files: int | None, per_file: int
            ) -> tuple[list[dict[str, object]], list[int], list[str]]:
    rng = random.Random(random_state)
    samples: list[tuple[Request, str]] = []
    seen = 0
    with ZipFile(archive_path) as archive:
        members = sorted(n for n in archive.namelist() if n.lower().endswith(".json"))
        if max_files and len(members) > max_files:
            members = sorted(rng.sample(members, max_files))
        for name in members:
            with archive.open(name) as source:
                document = ijson.items(source, "item")
                for file_index, item in enumerate(document):
                    if file_index >= per_file:
                        break
                    if not isinstance(item, dict):
                        continue
                    body = item.get("data", "")
                    if not isinstance(body, str):
                        body = json.dumps(body, separators=(",", ":"))
                    request = Request(
                        str(item.get("method", "GET")), str(item.get("url", "/"))[:65_536],
                        {str(k).lower(): str(v)[:8192] for k, v in dict(item.get("headers") or {}).items()},
                        body.encode("utf-8", "replace")[:65_536],
                    )
                    seen += 1
                    if maximum is None or len(samples) < maximum:
                        samples.append((request, name))
                    else:
                        position = rng.randrange(seen)
                        if position < maximum:
                            samples[position] = (request, name)
    rows = [extract(request).mapping() for request, _ in samples]
    labels = [label] * len(samples)
    groups = [name for _, name in samples]
    return rows, labels, groups


def prepare(malicious_zip: str | Path, legitimate_zip: str | Path,
            max_per_class: int = 100_000, random_state: int = 42
            ) -> tuple[pd.DataFrame, pd.Series, pd.Series, dict[str, object]]:
    malicious = records(malicious_zip, 1, max_per_class, random_state, None, 15_000)
    legitimate = records(legitimate_zip, 0, max_per_class, random_state + 1, 160, 800)
    rows = malicious[0] + legitimate[0]
    labels = malicious[1] + legitimate[1]
    groups = [f"malicious:{g}" for g in malicious[2]] + [f"legitimate:{g}" for g in legitimate[2]]
    frame = pd.DataFrame(rows, columns=FEATURES).astype(np.float32)
    target = pd.Series(labels, dtype=np.int8)
    return frame, target, pd.Series(groups), {
        "dataset": "openappsec-waf-comparison-2025-2026",
        "malicious_rows": len(malicious[0]), "legitimate_rows": len(legitimate[0]),
        "sampling_limit_per_class": max_per_class, "feature_count": len(FEATURES),
        "legitimate_source_sampling": "160 seeded files, first 800 requests per file",
        "malicious_source_sampling": "all files, first 15000 requests per file",
    }


def train(malicious_zip: str | Path, legitimate_zip: str | Path, output: str | Path = "artifacts",
          max_per_class: int = 100_000, random_state: int = 42) -> dict[str, object]:
    from xgboost import XGBClassifier

    destination = Path(output); destination.mkdir(parents=True, exist_ok=True)
    x, y, groups, audit = prepare(malicious_zip, legitimate_zip, max_per_class, random_state)
    splitter = GroupShuffleSplit(n_splits=30, test_size=0.25, random_state=random_state)
    selected = None
    for train_index, test_index in splitter.split(x, y, groups):
        if y.iloc[train_index].nunique() == y.iloc[test_index].nunique() == 2:
            selected = train_index, test_index; break
    if selected is None:
        raise ValueError("could not create source-file holdout containing both classes")
    train_index, test_index = selected
    model = XGBClassifier(n_estimators=220, max_depth=6, learning_rate=0.05, subsample=0.85,
                          colsample_bytree=0.85, min_child_weight=3, reg_lambda=3,
                          eval_metric="aucpr", n_jobs=-1, random_state=random_state)
    model.fit(x.iloc[train_index], y.iloc[train_index])
    probabilities = model.predict_proba(x.iloc[test_index])[:, 1]
    predictions = (probabilities >= 0.5).astype(np.int8)
    metrics = {"audit": audit, "split": {"strategy": "source-file-group-holdout",
               "train_sources": int(groups.iloc[train_index].nunique()),
               "test_sources": int(groups.iloc[test_index].nunique())},
               "train_rows": len(train_index), "test_rows": len(test_index),
               "roc_auc": float(roc_auc_score(y.iloc[test_index], probabilities)),
               "pr_auc": float(average_precision_score(y.iloc[test_index], probabilities)),
               "confusion_matrix": confusion_matrix(y.iloc[test_index], predictions).tolist(),
               "report": classification_report(y.iloc[test_index], predictions, output_dict=True, zero_division=0),
               "feature_importance": dict(zip(FEATURES, map(float, model.feature_importances_), strict=True))}
    model.save_model(destination / "xgboost.json")
    (destination / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (destination / "features.json").write_text(json.dumps({"version": 2, "dtype": "float32", "features": FEATURES}, indent=2), encoding="utf-8")
    export(model, destination / "model.inc")
    return metrics


def enrich(model_path: str | Path, output: str | Path, random_state: int = 42) -> None:
    """Extend a trained booster with React Server Components attack traffic."""
    import xgboost as xgb

    rng = random.Random(random_state)

    def row(request: Request) -> list[int | float]:
        return list(extract(request).mapping().values())

    def multipart(payload: str, boundary: str, padding: str = "") -> bytes:
        return (
            f'--{boundary}\r\nContent-Disposition: form-data; name="0"\r\n\r\n'
            f'{payload}{padding}\r\n--{boundary}\r\n'
            'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n--{boundary}--\r\n'
        ).encode()

    malicious: list[list[int | float]] = []
    probes = ["whoami", "id", "printf LATAUPE_PROBE", "echo probe", "uname -a"]
    for index in range(400):
        command = probes[index % len(probes)]
        prefix = (
            "try { process.mainModule.require('child_process')"
            f".execSync('{command}', {{timeout:{1000 + index % 9 * 1000}}}); "
            "throw Object.assign(new Error('NEXT_REDIRECT'), "
            "{digest:`success::${err.message}`}); } "
            "catch(err) { console.log(err); }"
        )
        payload = json.dumps({
            "then": "$1:__proto__:then", "status": "resolved_model", "reason": -1,
            "value": '{"then":"$B0"}',
            "_response": {"_prefix": prefix,
                          "_formData": {"get": "$1:constructor:constructor"}},
        }, separators=(",", ":"))
        boundary = f"----WebKitFormBoundary{index:08x}"
        headers = {"content-type": f"multipart/form-data; boundary={boundary}",
                   "next-action": "x"}
        malicious.append(row(Request("POST", "/action" if index % 2 else "/", headers,
                                     multipart(payload, boundary, " " * (index % 31)))))

    legitimate: list[list[int | float]] = []
    for index in range(1200):
        boundary = f"----Boundary{index:08x}"
        choices = (
            json.dumps({"name": f"user{index}", "message": "normal form submission"}),
            f"name=user{index}&description=photo upload&count={index}",
            f"const example = `hello ${{name}}`; console.log(example); item={index}",
            ("A normal multipart document with quotes ' and \" plus symbols; "
             * (1 + index % 8)),
        )
        headers = {"content-type": f"multipart/form-data; boundary={boundary}"}
        legitimate.append(row(Request("POST", "/upload", headers,
                                      multipart(choices[index % len(choices)], boundary,
                                                "x" * (index % 200)))))

    features = np.asarray(malicious + legitimate, dtype=np.float32)
    labels = np.asarray([1] * len(malicious) + [0] * len(legitimate), dtype=np.float32)
    order = list(range(len(labels)))
    rng.shuffle(order)

    booster = xgb.Booster()
    booster.load_model(model_path)
    matrix = xgb.DMatrix(features[order], label=labels[order],
                         feature_names=booster.feature_names)
    adapted = xgb.train({
        "objective": "binary:logistic", "eval_metric": "aucpr", "max_depth": 4,
        "eta": 0.06, "subsample": 0.9, "colsample_bytree": 0.9,
        "min_child_weight": 3, "lambda": 4, "seed": random_state,
    }, matrix, num_boost_round=35, xgb_model=booster)
    adapted.save_model(output)


def export(model, destination: str | Path) -> None:
    booster = model.get_booster() if hasattr(model, "get_booster") else model
    trees = [json.loads(value) for value in booster.get_dump(dump_format="json")]
    configuration = json.loads(booster.save_config())
    probability = float(str(configuration["learner"]["learner_model_param"]["base_score"]).strip("[]"))
    base_score = math.log(probability / (1.0 - probability))
    lines = ["// Generated by lataupe training; do not edit.",
             f"static constexpr float base_score = {literal(base_score)};", "static const TreeNode nodes[] = {"]
    roots, offset = [], 0
    for tree in trees:
        flattened: list[dict[str, object]] = []
        def visit(node: dict[str, object], flattened=flattened) -> int:
            position = len(flattened); flattened.append(node)
            if "leaf" not in node:
                children = {int(child["nodeid"]): child for child in node["children"]}
                node["yes_index"] = visit(children[int(node["yes"])]); node["no_index"] = visit(children[int(node["no"])])
            return position
        roots.append(offset + visit(tree))
        for node in flattened:
            if "leaf" in node:
                lines.append(f"    {{-1, 0.0f, -1, -1, {literal(node['leaf'])}}},")
            else:
                split = str(node["split"]); index = int(split[1:]) if split.startswith("f") and split[1:].isdigit() else FEATURES.index(split)
                lines.append(f"    {{{index}, {literal(node['split_condition'])}, {offset + int(node['yes_index'])}, {offset + int(node['no_index'])}, 0.0f}},")
        offset += len(flattened)
    lines += ["};", "static const int roots[] = {" + ", ".join(map(str, roots)) + "};"]
    Path(destination).write_text("\n".join(lines) + "\n", encoding="utf-8")
