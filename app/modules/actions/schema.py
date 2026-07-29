"""Parameter schemas for admin-defined actions.

This module is the security boundary for the actions feature. A diagnostic is
hardcoded and therefore safe by construction; an action is defined by an
administrator and is only as safe as what happens here.

Two rules do most of the work:

* **A placeholder is always exactly one argv token.** ``{name}`` may be a whole
  element of the template or nothing at all. It can never be spliced into a
  longer string, so a parameter cannot grow a second argument or become a flag.
* **SSH parameters must carry a regex pattern.** On the local path argv is a
  real boundary and metacharacters are inert. Over SSH they are not: sshd hands
  the command to the remote login shell, so the pattern is the only thing
  standing between a parameter and remote code execution. A schema without one
  is rejected at definition time rather than at run time.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any, Final

from app.core.validation import ValidationError

PARAM_TYPES: Final = ("string", "integer", "choice")

# A placeholder is a bare {name} occupying an entire template token.
PLACEHOLDER: Final = re.compile(r"^\{([a-z][a-z0-9_]{0,31})\}$", re.IGNORECASE)
# Used to spot a placeholder embedded in a larger token, which is refused.
EMBEDDED: Final = re.compile(r"\{[a-z][a-z0-9_]*\}", re.IGNORECASE)

PARAM_NAME: Final = re.compile(r"^[a-z][a-z0-9_]{0,31}$", re.IGNORECASE)

MAX_PARAMS: Final = 10
MAX_ARGV_TOKENS: Final = 32
MAX_STRING_LENGTH: Final = 256

# What a secret parameter looks like once it is safe to store or display.
MASK: Final = "[redacted]"

# Patterns an administrator might write that would not actually constrain
# anything. Each is refused with an explanation rather than silently accepted.
_USELESS_PATTERNS: Final = {".*", "^.*$", ".+", "^.+$", "", "^$", "(.*)", "^(.*)$"}


@dataclass(frozen=True)
class ParamSpec:
    name: str
    type: str = "string"
    pattern: str | None = None
    minimum: int | None = None
    maximum: int | None = None
    choices: list[str] | None = None
    required: bool = True
    secret: bool = False
    description: str | None = None


def parse_schema(raw: dict[str, Any], *, execution_type: str) -> dict[str, ParamSpec]:
    """Validate a stored param schema into specs, or explain why it is unusable."""
    if not isinstance(raw, dict):
        raise ValidationError("The parameter schema must be an object.")
    if len(raw) > MAX_PARAMS:
        raise ValidationError(f"An action may take at most {MAX_PARAMS} parameters.")

    specs: dict[str, ParamSpec] = {}

    for name, definition in raw.items():
        if not PARAM_NAME.match(str(name)):
            raise ValidationError(
                f"{name!r} is not a valid parameter name. Use letters, digits and "
                f"underscores, starting with a letter."
            )
        if not isinstance(definition, dict):
            raise ValidationError(f"The definition of {name!r} must be an object.")

        kind = definition.get("type", "string")
        if kind not in PARAM_TYPES:
            raise ValidationError(
                f"{name!r} has type {kind!r}; must be one of {', '.join(PARAM_TYPES)}."
            )

        pattern = definition.get("pattern")
        choices = definition.get("choices")

        if pattern is not None:
            if not isinstance(pattern, str):
                raise ValidationError(f"The pattern for {name!r} must be a string.")
            if pattern.strip() in _USELESS_PATTERNS:
                raise ValidationError(
                    f"The pattern for {name!r} matches anything, which is the same as "
                    f"having no pattern at all. Constrain it to what the command "
                    f"actually accepts."
                )
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValidationError(f"The pattern for {name!r} is not valid: {exc}") from exc

        # The rule that makes SSH actions safe at all. Enforced when the action
        # is defined, so an unsafe definition cannot be saved and then run.
        if execution_type == "ssh" and kind == "string" and not pattern and not choices:
            raise ValidationError(
                f"{name!r} needs a pattern or a fixed set of choices. SSH commands run "
                f"through the remote login shell, so argv provides no protection there "
                f"and the pattern is what prevents remote code execution."
            )

        if choices is not None:
            if not isinstance(choices, list) or not choices:
                raise ValidationError(f"The choices for {name!r} must be a non-empty list.")
            if not all(isinstance(choice, str) for choice in choices):
                raise ValidationError(f"Every choice for {name!r} must be a string.")

        specs[name] = ParamSpec(
            name=name,
            type=kind,
            pattern=pattern,
            minimum=_optional_int(definition.get("min"), name, "min"),
            maximum=_optional_int(definition.get("max"), name, "max"),
            choices=choices,
            required=bool(definition.get("required", True)),
            secret=bool(definition.get("secret", False)),
            description=definition.get("description"),
        )

    return specs


def _optional_int(value: object, name: str, field: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int | float | str):
        raise ValidationError(f"The {field} for {name!r} must be a whole number.")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"The {field} for {name!r} must be a whole number.") from exc


def validate_template(
    template: list[str], specs: dict[str, ParamSpec], *, execution_type: str
) -> None:
    """Check an argv template against its schema."""
    if not isinstance(template, list) or not template:
        raise ValidationError("The command template must be a non-empty list of tokens.")
    if len(template) > MAX_ARGV_TOKENS:
        raise ValidationError(f"The command template may have at most {MAX_ARGV_TOKENS} tokens.")
    if not all(isinstance(token, str) for token in template):
        raise ValidationError("Every token in the command template must be a string.")

    program = template[0]
    if PLACEHOLDER.match(program):
        raise ValidationError(
            "The program itself cannot be a parameter — that would let a parameter "
            "choose what runs."
        )

    used: set[str] = set()
    for token in template:
        match = PLACEHOLDER.match(token)
        if match:
            used.add(match.group(1))
            continue
        if EMBEDDED.search(token):
            # `--name={container}` looks harmless and is the crack through which
            # one parameter becomes two arguments, or a flag.
            raise ValidationError(
                f"{token!r} embeds a parameter inside a larger token. A parameter must "
                f"be a whole argument on its own, so pass it as a separate token."
            )

    unknown = used - set(specs)
    if unknown:
        raise ValidationError(
            f"The template uses {', '.join(sorted(unknown))}, which "
            f"{'is' if len(unknown) == 1 else 'are'} not defined in the schema."
        )

    unused = set(specs) - used
    if unused:
        raise ValidationError(
            f"The schema defines {', '.join(sorted(unused))}, which the template never "
            f"uses. Remove it, or reference it in the command."
        )

    if execution_type == "local":
        from app.core.execution import ExecutionRejected, resolve_binary

        # Resolved now so an unrunnable or forbidden program is refused at
        # definition time rather than failing for whoever first clicks it.
        # Translated to ValidationError because this surfaces on an admin form:
        # letting ExecutionRejected escape would turn "bash is not allowed" into
        # a 500 with no explanation.
        try:
            resolve_binary(program)
        except ExecutionRejected as exc:
            raise ValidationError(str(exc)) from exc


def coerce(value: object, spec: ParamSpec) -> str:
    """Validate one submitted parameter and return it as a string.

    Every rejection message names the parameter, because these are shown to an
    operator who is trying to get an action to run.
    """
    if value is None or value == "":
        if spec.required:
            raise ValidationError(f"{spec.name!r} is required.")
        return ""

    text = str(value)

    if len(text) > MAX_STRING_LENGTH:
        raise ValidationError(f"{spec.name!r} is longer than {MAX_STRING_LENGTH} characters.")

    if "\x00" in text:
        raise ValidationError(f"{spec.name!r} must not contain NUL bytes.")

    if spec.type == "integer":
        try:
            number = int(text)
        except ValueError as exc:
            raise ValidationError(f"{spec.name!r} must be a whole number.") from exc
        if spec.minimum is not None and number < spec.minimum:
            raise ValidationError(f"{spec.name!r} must be at least {spec.minimum}.")
        if spec.maximum is not None and number > spec.maximum:
            raise ValidationError(f"{spec.name!r} must be at most {spec.maximum}.")
        return str(number)

    if spec.choices is not None and text not in spec.choices:
        raise ValidationError(f"{spec.name!r} must be one of: {', '.join(spec.choices)}.")

    if spec.pattern is not None and not re.fullmatch(spec.pattern, text):
        # Deliberately does not echo the rejected value: it is attacker-supplied
        # and would land in an error page.
        raise ValidationError(f"{spec.name!r} does not match the required format for this action.")

    return text


def build_argv(
    template: list[str], specs: dict[str, ParamSpec], values: dict[str, object]
) -> list[str]:
    """Substitute validated parameters into an argv list.

    One token in, one token out. Nothing is joined, split, or interpolated, so a
    parameter containing shell metacharacters is passed to the program as one
    literal string — there is no shell to interpret it.
    """
    argv: list[str] = []

    for token in template:
        match = PLACEHOLDER.match(token)
        if not match:
            argv.append(token)
            continue

        name = match.group(1)
        spec = specs[name]
        argv.append(coerce(values.get(name), spec))

    return argv


def build_ssh_command(
    template: list[str], specs: dict[str, ParamSpec], values: dict[str, object]
) -> str:
    """Assemble the single command string that will be sent to a remote sshd.

    This is where the local and remote paths genuinely differ. Over SSH there is
    no argv — sshd receives one string and hands it to the target user's login
    shell. So every substituted value is quoted with :func:`shlex.quote`, and
    that quoting is the second line of defence behind the mandatory pattern.

    Neither is as strong as restricting the key on the target with
    ``command="..."``; see docs/SUDOERS_EXAMPLE.md.
    """
    parts: list[str] = []

    for token in template:
        match = PLACEHOLDER.match(token)
        if not match:
            # Template tokens are administrator-written and fixed, but they are
            # quoted too — an action name is not a reason to trust a string.
            parts.append(shlex.quote(token))
            continue

        name = match.group(1)
        parts.append(shlex.quote(coerce(values.get(name), specs[name])))

    return " ".join(parts)


def build_preview(
    template: list[str],
    specs: dict[str, ParamSpec],
    values: dict[str, object],
    *,
    quote: bool = False,
) -> str:
    """Build the human-readable record of what ran, with secrets masked.

    Separate from :func:`build_argv` and :func:`build_ssh_command` on purpose.
    Those produce what is actually executed and are never stored; this produces
    what is written to the execution record and shown in the audit log.

    Collapsing the two would put a parameter flagged ``secret`` into the
    database in plaintext and render it on a page — which is precisely the leak
    that masking ``params_redacted`` alone was supposed to prevent, arriving
    through a different field.

    ``quote`` mirrors the SSH path so the preview reflects the quoting that was
    actually applied.
    """
    parts: list[str] = []

    for token in template:
        match = PLACEHOLDER.match(token)
        if not match:
            parts.append(shlex.quote(token) if quote else token)
            continue

        spec = specs[match.group(1)]
        # Values have already been validated by the time a preview is built, so
        # coerce cannot raise here; it is reused so the preview shows exactly
        # what was substituted.
        value = MASK if spec.secret else coerce(values.get(spec.name), spec)
        parts.append(shlex.quote(value) if quote else value)

    return " ".join(parts)


def redact(values: dict[str, object], specs: dict[str, ParamSpec]) -> dict[str, object]:
    """Mask anything the schema flagged secret, before it is stored."""
    return {
        name: (MASK if name in specs and specs[name].secret else value)
        for name, value in values.items()
    }
