"""Tool manifest schema (plan section 8.1). One YAML file per tool in tools/.

Validation enforces the safety rules before a manifest is trusted:
- launch args are a fixed list; placeholders must be a whole argument and come
  from a closed set, and target placeholders must match declared target types
- executables live only under envs/ (per-tool venvs) or bin/ (pinned binaries)
- a tool is either local or external, and active tools name the Settings switch
  that gates them (rule 5)
"""

from __future__ import annotations

import re
from datetime import date
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.validation import TargetType


class Category(str, Enum):
    USERNAMES = "usernames"
    EMAIL = "email"
    PHONE = "phone"
    IP = "ip"
    DOMAINS = "domains"
    IMAGES = "images"
    ARCHIVES = "archives"
    WEB = "web"
    SOCIAL = "social"
    THREAT = "threat"
    AI = "ai"
    GENERAL = "general"

    @property
    def label(self) -> str:
        return CATEGORY_LABELS[self]


CATEGORY_LABELS = {
    Category.USERNAMES: "Usernames",
    Category.EMAIL: "Email",
    Category.PHONE: "Phone",
    Category.IP: "IP",
    Category.DOMAINS: "Domains",
    Category.IMAGES: "Images",
    Category.ARCHIVES: "Archives",
    Category.WEB: "Web research",
    Category.SOCIAL: "Social networks",
    Category.THREAT: "Threat intel",
    Category.AI: "AI tools",
    Category.GENERAL: "General",
}


class Label(str, Enum):
    LOCAL = "local"
    EXTERNAL = "external"
    PASSIVE = "passive"
    ACTIVE = "active"
    API_KEY = "api_key"


class LaunchKind(str, Enum):
    SUBPROCESS = "subprocess"  # separate venv or pinned binary, run via QProcess
    PYTHON = "python"          # library imported by a built-in module
    WEB_API = "web_api"        # HTTPS API called by a built-in module
    BROWSER = "browser"        # opened in the browser, nothing runs locally


#: Placeholders the runner may substitute. Target types plus run paths. "other" is free text: never an argument.
RUN_PLACEHOLDERS = {"out_file", "work_dir"}
ALLOWED_PLACEHOLDERS = {t.value for t in TargetType if t is not TargetType.OTHER} | RUN_PLACEHOLDERS
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
_ID = re.compile(r"^[a-z0-9][a-z0-9_]{1,40}$")
_PARSER = re.compile(r"^adapters\.[a-z0-9_]+:[a-z_][a-z0-9_]*$")
_REL_PATH = re.compile(r"^[A-Za-z0-9_./-]+$")


class Launch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: LaunchKind
    venv: str | None = None          # subprocess: envs/<tool>
    executable: str | None = None    # subprocess: bin/<binary>.exe
    module: str | None = None        # python: importable module name
    sha256: str | None = None        # pinned hash of a bin/ executable, checked before every run
    tree: str | None = None          # a bin/ folder the executable runs from (exiftool_files)
    tree_sha256: str | None = None   # pinned hash of that whole folder (core.runner.tree_sha256)
    script: str | None = None        # subprocess: a .py file under envs/ run by the venv's python
    cwd: Literal["work_dir", "script"] = "work_dir"  # "script": tools that read data relative to themselves
    args: tuple[str, ...] = ()       # empty until the adapter is integrated
    own_home: bool = False  # the tool's home folder is its run folder, so its data stays with the case
    stderr: Literal["console", "file"] = "console"  # "file": stderr goes to stderr.log in the run folder
    timeout_s: int = Field(180, ge=5, le=3600)
    max_output_kb: int = Field(2048, ge=16, le=65536)

    @field_validator("venv", "executable", "script", "tree")
    @classmethod
    def _relative_path(cls, value: str | None, info) -> str | None:
        if value is None:
            return value
        root = "bin/" if info.field_name in ("executable", "tree") else "envs/"
        if not _REL_PATH.match(value) or ".." in value or not value.startswith(root):
            raise ValueError(f"{info.field_name} must be a plain path under {root}")
        # CreateProcess runs .bat/.cmd through cmd.exe, which would re-parse the arguments.
        if info.field_name == "executable" and not value.lower().endswith(".exe"):
            raise ValueError("executable must be an .exe")
        return value

    @field_validator("sha256", "tree_sha256")
    @classmethod
    def _sha256(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return value

    @field_validator("args")
    @classmethod
    def _fixed_args(cls, args: tuple[str, ...]) -> tuple[str, ...]:
        for arg in args:
            found = _PLACEHOLDER.findall(arg)
            if not found:
                continue
            if arg != "{" + found[0] + "}" or len(found) != 1:
                raise ValueError(f"placeholder must be a whole argument: {arg!r}")
            if found[0] not in ALLOWED_PLACEHOLDERS:
                raise ValueError(f"unknown placeholder {{{found[0]}}}")
        return args

    @model_validator(mode="after")
    def _kind_fields(self) -> Launch:
        if self.kind is LaunchKind.SUBPROCESS and not (self.venv or self.executable):
            raise ValueError("subprocess tools need a venv (envs/...) or an executable (bin/...)")
        if self.kind is LaunchKind.PYTHON and not self.module:
            raise ValueError("python tools need the module name")
        if self.kind is not LaunchKind.SUBPROCESS and (self.venv or self.executable or self.args):
            raise ValueError("only subprocess tools may set venv, executable or args")
        if self.executable and not self.sha256:
            raise ValueError("a bin/ executable needs its pinned sha256")
        if self.sha256 and not self.executable:
            raise ValueError("sha256 pins a bin/ executable")
        if bool(self.tree) != bool(self.tree_sha256) or (self.tree and not self.executable):
            raise ValueError("tree and tree_sha256 pin a bin/ executable's folder together")
        if self.script and not (self.venv and self.script.endswith(".py")):
            raise ValueError("script must be a .py file run by the tool's venv")
        if self.cwd == "script" and not self.script:
            raise ValueError("cwd: script needs a script")
        return self

    def placeholders(self) -> set[str]:
        return {_PLACEHOLDER.findall(a)[0] for a in self.args if _PLACEHOLDER.search(a)}


class ToolManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str = Field(min_length=1, max_length=60)
    category: Category
    description: str = Field(min_length=1, max_length=300)
    limitations: str = Field(min_length=1, max_length=600)
    official_url: str
    license: str | None = None
    open_source: bool
    labels: tuple[Label, ...]
    target_types: tuple[TargetType, ...] = ()
    provider: str | None = Field(None, max_length=200)  # "Sent to" in the consent dialog
    api_key: Literal["none", "optional", "required"] = "none"
    active_setting: str | None = None
    launch: Launch
    parser: str | None = None
    review_date: date

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID.match(value):
            raise ValueError("id must be lowercase letters, digits and underscores")
        return value

    @field_validator("official_url")
    @classmethod
    def _https(cls, value: str) -> str:
        if not re.match(r"^https://[a-z0-9.-]+\.[a-z]{2,}(/\S*)?$", value):
            raise ValueError("official_url must be an https:// link")
        return value

    @field_validator("parser")
    @classmethod
    def _parser(cls, value: str | None) -> str | None:
        if value is not None and not _PARSER.match(value):
            raise ValueError("parser must look like adapters.<module>:<function>")
        return value

    @field_validator("labels")
    @classmethod
    def _labels(cls, labels: tuple[Label, ...]) -> tuple[Label, ...]:
        if len(set(labels)) != len(labels):
            raise ValueError("labels contain duplicates")
        if (Label.LOCAL in labels) == (Label.EXTERNAL in labels):
            raise ValueError("a tool is either local or external (exactly one of them)")
        return labels

    @model_validator(mode="after")
    def _consistency(self) -> ToolManifest:
        if (self.api_key != "none") != (Label.API_KEY in self.labels):
            raise ValueError("the api_key label must match the api_key field")
        if Label.ACTIVE in self.labels:
            if not (self.active_setting or "").startswith("active."):
                raise ValueError("active tools must name their Settings switch (active.<name>)")
        elif self.active_setting:
            raise ValueError("active_setting is only for tools labeled active")
        declared = {t.value for t in self.target_types}
        missing = self.launch.placeholders() - RUN_PLACEHOLDERS - declared
        if missing:
            raise ValueError(f"args use undeclared target types: {sorted(missing)}")
        return self

    # ---- display helpers

    @property
    def is_local(self) -> bool:
        return Label.LOCAL in self.labels

    @property
    def is_active(self) -> bool:
        return Label.ACTIVE in self.labels

    @property
    def display_tags(self) -> list[str]:
        """Tag kinds in prototype order, plus 'oss' for open-source tools."""
        order = [Label.LOCAL, Label.EXTERNAL, Label.PASSIVE, Label.ACTIVE, Label.API_KEY]
        tags = [label.value for label in order if label in self.labels]
        return tags + (["oss"] if self.open_source else [])

    @property
    def monogram(self) -> str:
        words = re.findall(r"[A-Za-z0-9]+", self.name)
        if len(words) >= 2:
            return (words[0][0] + words[1][0]).upper()
        return self.name[:2].upper()

    @property
    def short_url(self) -> str:
        return self.official_url.removeprefix("https://").removeprefix("www.").rstrip("/")
