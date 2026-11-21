"""Regression tests for NEXUS CLI registration and startup branding."""

from shadow313.cli.main import _required_namespaces, build_parser
from shadow313.core.kernel import Kernel
from shadow313.core.output import OutputFormatter


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
    assert "LOCAL-FIRST SECURITY OPERATIONS" in output
    assert "Ottawa" not in output
    assert "╭" in output and "╰" in output
