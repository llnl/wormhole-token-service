from pathlib import Path

import pytest

from token_service.utils import expand_path


@pytest.fixture
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    monkeypatch.setenv("HOME", str(path))
    return str(path)


@pytest.mark.parametrize("value", [None, ""], ids=["none", "empty"])
def test_expand_path_returns_empty_string_for_unset_values(value):
    assert expand_path(value) == ""


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("$HOME/x.keytab", id="dollar"),
        pytest.param("${HOME}/x.keytab", id="braced"),
        pytest.param("~/x.keytab", id="tilde"),
    ],
)
def test_expand_path_expands_home(home, value):
    assert expand_path(value) == f"{home}/x.keytab"


def test_expand_path_expands_environment_variable(monkeypatch):
    monkeypatch.setenv("WORMHOLE_KEYTAB_DIR", "/etc/wormhole")
    assert expand_path("$WORMHOLE_KEYTAB_DIR/x.keytab") == "/etc/wormhole/x.keytab"


def test_expand_path_leaves_an_unset_variable_in_place(monkeypatch):
    monkeypatch.delenv("WORMHOLE_UNSET_VAR", raising=False)
    assert expand_path("$WORMHOLE_UNSET_VAR/x.keytab") == "$WORMHOLE_UNSET_VAR/x.keytab"


def test_expand_path_passes_an_absolute_path_through_unchanged():
    assert expand_path("/etc/wormhole/x.keytab") == "/etc/wormhole/x.keytab"


def test_expand_path_does_not_resolve_a_relative_path():
    assert expand_path("./x.keytab") == "./x.keytab"


def test_expand_path_leaves_an_already_resolved_dynaconf_format_value_alone(home):
    """By the time Dynaconf hands over an `@format` value it is absolute.

    `@format {env[HOME]}/x.keytab` arrives here already resolved, so a second
    pass must be a no-op.
    """

    resolved = f"{home}/x.keytab"
    assert expand_path(resolved) == resolved


def test_expand_path_accepts_a_path_object(home):
    result = expand_path(Path("~/x.keytab"))
    assert result == f"{home}/x.keytab"
    assert isinstance(result, str)


def test_expand_path_does_not_expand_a_tilde_produced_by_a_variable(monkeypatch):
    monkeypatch.setenv("WORMHOLE_KEYTAB_DIR", "~/wormhole")
    assert expand_path("$WORMHOLE_KEYTAB_DIR/x.keytab") == "~/wormhole/x.keytab"
