"""Regression tests for NEXUS CLI registration and startup branding."""

from shadow313.cli.main import _dispatch, _required_namespaces, build_parser
from shadow313.core.kernel import Kernel
from shadow313.core.output import OutputFormatter


def test_builtin_module_names_are_unique():
    names = [name for name, _ in Kernel._BUILTIN_MODULES]
    assert len(names) == len(set(names))


def test_nexus_temporal_and_stix_handlers_are_autoloaded():
    builtins = dict(Kernel._BUILTIN_MODULES)
    assert builtins["nexus"] == "shadow313.v4.nexus.nexus.NEXUSModule"
    assert builtins["temporal"] == (
        "shadow313.v4.temporal_binding.temporal_binding.TemporalBindingModule"
    )
    assert builtins["stix"] == "shadow313.v4.stix.stix_handler.STIXModule"
    assert builtins["finetune"] == "shadow313.v4.finetune_ui.finetune_ui.FineTuneModule"
    assert builtins["mobile_api"] == "shadow313.v4.mobile_api.mobile_api.MobileAPIModule"


def test_nexus_command_requires_registered_nexus_handler():
    args = build_parser().parse_args(["nexus", "--status"])
    assert _required_namespaces(args) == ["nexus"]


def test_temporal_command_requires_registered_temporal_handler():
    args = build_parser().parse_args(["temporal", "--list-receipts"])
    assert _required_namespaces(args) == ["temporal"]


def test_stix_command_requires_registered_stix_handler():
    args = build_parser().parse_args(["stix", "--export"])
    assert _required_namespaces(args) == ["stix"]


def test_commands_directory_is_a_supported_cli_command():
    args = build_parser().parse_args(["commands"])
    assert args.command == "commands"
    assert _required_namespaces(args) == []


def test_startup_banner_is_boxed_and_has_no_location(capsys):
    formatter = OutputFormatter(fmt="plain", color=False)
    formatter.banner()
    output = capsys.readouterr().out
    assert "SHADOW313" in output
    assert "NEXUS" in output
    assert "LOCAL-FIRST AI-POWERED SECURITY INTELLIGENCE" in output
    assert "Ottawa" not in output
    assert "╔" in output and "╚" in output




def test_update_command_requires_only_the_selected_module_handlers():
    cases = {
        "cve": ["vuln"],
        "exploitdb": [],
        "kev": ["kev"],
        "epss": ["epss"],
        "all": ["vuln", "kev", "epss"],
    }
    for database, expected in cases.items():
        args = build_parser().parse_args(["update", "--db", database])
        assert _required_namespaces(args) == expected


def test_advanced_nexus_cli_commands_have_registered_handlers():
    cases = {
        "orchestrate": ["orchestrate", "--intent", "summarize security posture"],
        "nexus-router": ["nexus-router", "--health"],
        "ledger": ["ledger", "--stats"],
        "workflow": ["workflow", "--list"],
        "tools": ["tools", "--list-tools"],
        "simulate": ["simulate", "--sim", "ndi"],
        "collab": ["collab", "--list"],
        "attack-map": ["attack-map", "--technique-summary"],
        "pe-analyze": ["pe-analyze", "--entropy"],
        "dns-intercept": ["dns-intercept", "--scan-ot"],
    }
    for command, argv in cases.items():
        args = build_parser().parse_args(argv)
        assert args.command == command
        assert _required_namespaces(args) == [command.replace("-", "_")]



def test_dns_intercept_command_dispatches_to_canonical_handler():
    class FakeKernel:
        def __init__(self):
            self.calls = []

        def dispatch(self, namespace, **kwargs):
            self.calls.append((namespace, kwargs))

    kernel = FakeKernel()
    parser = build_parser()
    args = parser.parse_args(["dns-intercept", "--scan-ot"])

    assert _dispatch(kernel, args, parser) == 0
    assert kernel.calls[0][0] == "dns_intercept"


def test_advanced_commands_are_in_command_directory():
    args = build_parser().parse_args(["commands", "--all"])
    assert args.command == "commands"
    assert _required_namespaces(args) == []
