"""GGUF metadata, weight registration, and route resolution."""

import struct

import pytest

from veritas.models.gguf import GgufError, read_metadata
from veritas.models.profiles import PROFILES, RouteUnavailable, Routing
from veritas.models.registry import RegisteredModel, RegistryError, default_name, register


def gguf_string(text):
    data = text.encode()
    return struct.pack("<Q", len(data)) + data


def gguf_file(path, kvs, version=3):
    data = b"GGUF" + struct.pack("<IQQ", version, 291, len(kvs))
    for key, vtype, payload in kvs:
        data += gguf_string(key) + struct.pack("<I", vtype) + payload
    path.write_bytes(data + b"\x00" * 64)  # tensor data follows the header; it is never read
    return path


def standard_kvs(template=True, license_id="apache-2.0"):
    kvs = [
        ("general.architecture", 8, gguf_string("qwen3")),
        ("general.name", 8, gguf_string("Qwen3 4B Instruct 2507")),
        ("general.file_type", 4, struct.pack("<I", 15)),
        ("qwen3.context_length", 4, struct.pack("<I", 262144)),
        ("tokenizer.ggml.tokens", 9, struct.pack("<IQ", 8, 3) + b"".join(gguf_string(t) for t in "abc")),
        ("tokenizer.ggml.scores", 9, struct.pack("<IQ", 6, 3) + struct.pack("<3f", 0.1, 0.2, 0.3)),
    ]
    if license_id:
        kvs.append(("general.license", 8, gguf_string(license_id)))
    if template:
        kvs.append(("tokenizer.chat_template", 8, gguf_string("{% for m in messages %}{{ m.content }}{% endfor %}")))
    return kvs


def test_metadata_is_read_and_arrays_are_skipped(tmp_path):
    info = read_metadata(gguf_file(tmp_path / "m.gguf", standard_kvs()))
    assert (info.version, info.tensors, info.architecture, info.name) == (3, 291, "qwen3", "Qwen3 4B Instruct 2507")
    assert (info.quantization, info.context_length, info.license, info.chat_template) == (
        "Q4_K_M",
        262144,
        "apache-2.0",
        True,
    )


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        (b"NOPE" + b"\x00" * 32, "not a GGUF file"),
        (b"GGUF" + struct.pack("<IQQ", 1, 0, 0), "version 1 is not supported"),
        (b"GGUF" + struct.pack("<IQQ", 3, 0, 10**9), "metadata entries exceed the limit"),
        (b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + struct.pack("<Q", 10**12), "exceeds the 256-byte limit"),
        (b"GGUF" + struct.pack("<IQQ", 3, 0, 2) + gguf_string("general.name"), "ends inside its metadata header"),
    ],
)
def test_malformed_headers_are_refused(tmp_path, data, fragment):
    path = tmp_path / "bad.gguf"
    path.write_bytes(data)
    with pytest.raises(GgufError, match=fragment):
        read_metadata(path)


def test_register_hashes_records_and_installs(tmp_path):
    path = gguf_file(tmp_path / "Qwen3-4B-Instruct-2507-Q4_K_M.gguf", standard_kvs())
    installed = []
    entry, models = register(path, {}, lambda *args: installed.append(args))
    assert entry.name == "qwen3-4b-instruct-2507-q4_k_m" == default_name(path)
    assert (entry.license, entry.quantization, entry.permissive) == ("apache-2.0", "Q4_K_M", True)
    assert installed == [(path, entry.file, entry.sha256.removeprefix("sha256:"))]
    assert RegisteredModel.from_json(models[entry.name]) == entry
    with pytest.raises(RegistryError, match="already registered"):
        register(path, {"models": models}, lambda *args: None)
    with pytest.raises(RegistryError, match="already registered under another name"):
        register(path, {"models": models}, lambda *args: None, name="copy")


def test_register_requires_a_license_and_a_chat_template(tmp_path):
    unlicensed = gguf_file(tmp_path / "a.gguf", standard_kvs(license_id=None))
    with pytest.raises(RegistryError, match="declares no license"):
        register(unlicensed, {}, lambda *args: None)
    entry, _ = register(unlicensed, {}, lambda *args: None, license_id="MIT")
    assert entry.license == "mit"
    with pytest.raises(RegistryError, match="no chat template"):
        register(gguf_file(tmp_path / "b.gguf", standard_kvs(template=False)), {}, lambda *args: None)
    with pytest.raises(RegistryError, match="lowercase letters"):
        register(unlicensed, {}, lambda *args: None, name="Bad Name", license_id="mit")


def model(name):
    return RegisteredModel(name, f"sha256:{name:0<64}", 1, f"{name}.gguf", "mit", "Q4_K_M", "qwen3", 8192, name, "t")


def test_routes_resolve_through_explicit_aliases():
    routing = Routing(PROFILES["laptop"], {"analysis": "small"}, {"small": model("small")})
    deep = routing.resolve("deep")
    assert (deep.serving, deep.model.name, deep.aliased, deep.source) == ("analysis", "small", True, "workspace")
    assert routing.resolve("analysis").aliased is False
    assert routing.escalate("triage") is None  # every route is the same model on this profile


def test_a_workspace_choice_overrides_an_alias_and_enables_escalation():
    models = {"small": model("small"), "big": model("big")}
    routing = Routing(PROFILES["laptop"], {"triage": "small", "analysis": "big"}, models)
    assert routing.resolve("triage").model.name == "small"
    assert routing.escalate("triage") == "analysis"


def test_the_code_route_uses_a_small_coding_model_when_chosen_and_analysis_otherwise():
    general, coder = model("general"), model("coder")
    without = Routing(PROFILES["laptop"], {"analysis": "general"}, {"general": general})
    code = without.resolve("code")
    assert (code.serving, code.model.name, code.aliased) == ("analysis", "general", True)
    chosen = Routing(PROFILES["laptop"], {"analysis": "general", "code": "coder"}, {"general": general, "coder": coder})
    assert (chosen.resolve("code").model.name, chosen.resolve("code").aliased) == ("coder", False)
    assert chosen.escalate("code") == "analysis"  # a task the small model fails twice moves up


def test_a_small_model_gets_a_longer_context_in_the_same_memory():
    laptop = PROFILES["laptop"]
    small = RegisteredModel("coder", "sha256:" + "c" * 64, 1_100_000_000, "c.gguf", "apache-2.0", "Q4_K_M", "qwen2",
                            32768, "Coder 1.5B", "t")  # fmt: skip
    large = RegisteredModel("general", "sha256:" + "d" * 64, 2_500_000_000, "g.gguf", "apache-2.0", "Q4_K_M", "qwen3",
                            32768, "General 4B", "t")  # fmt: skip
    assert (laptop.limits_for(small).context, laptop.limits_for(small).memory) == (8192, laptop.limits.memory)
    assert laptop.limits_for(large) == laptop.limits


def test_unavailable_routes_say_what_to_do():
    with pytest.raises(RouteUnavailable, match="veritas models route analysis"):
        Routing(PROFILES["laptop"], {}, {}).resolve("triage")
    with pytest.raises(RouteUnavailable, match="not registered"):
        Routing(PROFILES["laptop"], {"analysis": "gone"}, {}).resolve("analysis")
