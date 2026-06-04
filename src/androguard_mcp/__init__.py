"""Core analysis engine wrapping androguard.

All public methods return structured dicts/lists with hard output limits.
Generators are consumed with itertools.islice — never fully materialized.
Byte arrays are truncated. Instruction dumps have pagination.
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Any

from androguard.core.analysis.analysis import Analysis, MethodAnalysis
from androguard.core.apk import APK
from androguard.core.dex import DEX

# ---- Hard limits: never exceed these in any output ----
MAX_STRING_RESULTS   = 50
MAX_CLASS_RESULTS    = 50
MAX_FIELD_DISPLAY    = 30
MAX_METHOD_DISPLAY   = 30
MAX_XREF_DISPLAY     = 15
MAX_BYTECODE_INSTRS  = 60        # per page
MAX_BYTECODE_SHOW_LEN = 200      # truncate instr.show() text
MAX_PERMISSIONS      = 50
MAX_ACTIVITIES       = 20
MAX_STRING_LEN       = 300       # truncate individual string values
MAX_XREF_COUNT       = 200       # max xref items to materialise for counting

# ---- Dataclasses for structured output ----

@dataclass
class FieldInfo:
    name: str
    type: str
    access: str
    init_value: str | None

@dataclass
class MethodSummary:
    name: str
    descriptor: str
    access: str
    instr_count: int

@dataclass
class Instruction:
    idx: int
    op: str
    show: str | None

@dataclass
class ClassSummary:
    name: str
    superclass: str
    interfaces: list[str]
    access: str
    fields: list[FieldInfo]
    total_fields: int
    methods: list[MethodSummary]
    total_methods: int
    xref_from: list[str]

@dataclass
class StaticFieldInfo:
    name: str
    type: str
    init_hex: str | None
    init_bytes: list[int] | None
    init_label: str | None

@dataclass
class MethodInfo:
    signature: str
    access: str
    instr_count: int
    callers: list[str]
    total_callers: int
    top_callee_classes: dict[str, int]

@dataclass
class XrefResult:
    signature: str
    callers: list[str]
    total_callers: int
    callees: list[str]
    total_callees: int

@dataclass
class ManifestSummary:
    package: str
    version_name: str
    version_code: str
    min_sdk: int
    target_sdk: int
    app_name: str
    permissions: list[str]
    total_permissions: int
    activities: list[str]
    total_activities: int
    services: list[str]
    total_services: int
    receivers: list[str]
    total_receivers: int


# ---- Helpers ----

def _safe_len(gen_or_list: Any) -> int:
    """Get length without materializing a generator.  Returns -1 if unknown."""
    if hasattr(gen_or_list, "__len__"):
        return len(gen_or_list)
    return -1


def _take(n: int, gen_or_list: Any) -> list[Any]:
    """Take at most n items from a generator or list."""
    if hasattr(gen_or_list, "__getitem__"):
        return gen_or_list[:n]
    return list(itertools.islice(gen_or_list, n))


def _take_from_generator(n: int, gen: Any) -> list[Any]:
    return list(itertools.islice(gen, n))


def _truncate(s: str, max_len: int = MAX_STRING_LEN) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + f"…<truncated {len(s) - max_len} chars>"


def _hex_bytes(data: list[int], max_len: int = 64) -> str:
    """Convert int list to hex string, truncating large arrays."""
    if len(data) <= max_len:
        return bytes(data).hex()
    return bytes(data[:max_len]).hex() + f"…<{len(data)} bytes>"


def _is_const_string(instr: Any) -> bool:
    try:
        return instr.get_name() in ("const-string", "const-string/jumbo")
    except Exception:
        return False


# ---------------------------------------------------------------------------
# APKAnalyzer
# ---------------------------------------------------------------------------

class APKAnalyzer:
    """Holds loaded APK state and provides safe, bounded analysis primitives."""

    def __init__(self) -> None:
        self.apk: APK | None = None
        self.dex_list: list[DEX] = []
        self.analysis: Analysis | None = None
        self.path: str = ""
        # name → (DEX, ClassDefItem, dex_index) — built in load(), O(1) lookup
        self._class_cache: dict[str, tuple[Any, Any, int]] = {}

    # ---- properties ----

    @property
    def loaded(self) -> bool:
        return self.analysis is not None

    # ---- load ----

    def load(self, apk_path: str) -> dict[str, Any]:
        from androguard.misc import AnalyzeAPK

        self.apk, self.dex_list, self.analysis = AnalyzeAPK(apk_path)
        self.path = apk_path

        self._class_cache = {}
        for i, dx in enumerate(self.dex_list):
            for cls in dx.get_classes():
                self._class_cache[cls.get_name()] = (dx, cls, i)

        return {
            "package": self.apk.get_package(),
            "version": self.apk.get_androidversion_name(),
            "min_sdk": self.apk.get_min_sdk_version(),
            "target_sdk": self.apk.get_target_sdk_version(),
            "dex_count": len(self.dex_list),
            "class_count": len(self._class_cache),
            "string_count": sum(len(d.get_strings()) for d in self.dex_list),
            "permission_count": len(self.apk.get_permissions()),
        }

    # ---- dex lookup ----

    def find_dex_for_class(self, class_name: str) -> tuple[Any, int] | None:
        if not self.loaded:
            return None
        entry = self._class_cache.get(class_name)
        if entry is None:
            return None
        return entry[0], entry[2]

    def _cls(self, class_name: str) -> Any | None:
        """Return the ClassDefItem for a class name, or None."""
        entry = self._class_cache.get(class_name)
        return entry[1] if entry else None

    # ---- string search ----

    def search_strings(self, pattern: str, limit: int = MAX_STRING_RESULTS) -> list[str]:
        """Return matching strings (truncated), bounded by limit."""
        if not self.loaded:
            return []
        pat = re.compile(pattern, re.IGNORECASE)
        results: list[str] = []
        for di, dx in enumerate(self.dex_list):
            for s in dx.get_strings():
                if pat.search(s):
                    results.append(f"[DEX{di}] {_truncate(s)!r}")
                    if len(results) >= limit:
                        return results
        return results

    # ---- class search ----

    def search_classes(self, pattern: str, limit: int = MAX_CLASS_RESULTS) -> list[str]:
        """Return matching class names, bounded by limit."""
        if not self.loaded:
            return []
        pat = re.compile(pattern, re.IGNORECASE)
        results: list[str] = []
        for di, dx in enumerate(self.dex_list):
            for name in dx.get_classes_names():
                if pat.search(name):
                    results.append(f"[DEX{di}] {name}")
                    if len(results) >= limit:
                        return results
        return results

    # ---- string refs ----

    def find_string_refs(
        self, string: str, dex_index: int | None = None
    ) -> list[str]:
        """Find methods referencing a string.  Returns at most MAX_STRING_RESULTS."""
        if not self.loaded:
            return []
        results: list[str] = []
        dex_range = (
            enumerate(self.dex_list)
            if dex_index is None
            else [(dex_index, self.dex_list[dex_index])]
        )
        for di, dx in dex_range:
            tidx = self._find_string_index(dx, string)
            if tidx is None:
                continue
            for cls in dx.get_classes():
                for m in cls.get_methods():
                    code = m.get_code()
                    if code is None:
                        continue
                    bc = code.get_bc()
                    for instr in bc.get_instructions():
                        if _is_const_string(instr) and instr.get_string() == string:
                            sig = f"[DEX{di}] {m.get_class_name()}->{m.get_name()}{m.get_descriptor()}"
                            results.append(sig)
                            break
                    if len(results) >= MAX_STRING_RESULTS:
                        return results
        return results

    # ---- class summary ----

    def get_class_summary(self, class_name: str) -> ClassSummary | None:
        r = self.find_dex_for_class(class_name)
        if r is None:
            return None
        cls = self._cls(class_name)
        if cls is None:
            return None
        ca = self.analysis.get_class_analysis(class_name) if self.loaded else None

        all_fields = cls.get_fields()
        fields = []
        for f in all_fields[:MAX_FIELD_DISPLAY]:
            f_info = FieldInfo(
                name=f.get_name(),
                type=f.get_descriptor(),
                access=f.get_access_flags_string() or "",
                init_value=None,
            )
            iv = f.get_init_value()
            if iv is not None:
                try:
                    if isinstance(iv, list):
                        f_info.init_value = _hex_bytes(iv) if len(iv) <= 64 else f"byte[{len(iv)}]"
                    else:
                        f_info.init_value = _truncate(str(iv), 64)
                except Exception:
                    f_info.init_value = "<error>"
            fields.append(f_info)

        all_methods = cls.get_methods()
        methods = []
        for m in all_methods[:MAX_METHOD_DISPLAY]:
            code = m.get_code()
            real_count = 0
            if code is not None:
                real_count = len(_take_from_generator(MAX_BYTECODE_INSTRS + 1, code.get_bc().get_instructions()))

            methods.append(MethodSummary(
                name=m.get_name(),
                descriptor=m.get_descriptor(),
                access=m.get_access_flags_string() or "",
                instr_count=real_count,
            ))

        xref_from: list[str] = []
        if ca:
            for ref in _take(MAX_XREF_DISPLAY, ca.get_xref_from()):
                xref_from.append(f"{ref[1].name}{ref[1].descriptor} in {ref[0].name}")

        return ClassSummary(
            name=class_name,
            superclass=cls.get_superclassname(),
            interfaces=_take(10, cls.get_interfaces()),
            access=cls.get_access_flags_string() or "",
            fields=fields,
            total_fields=len(all_fields),
            methods=methods,
            total_methods=len(all_methods),
            xref_from=xref_from,
        )

    # ---- static fields ----

    def get_static_fields(self, class_name: str) -> list[StaticFieldInfo] | None:
        r = self.find_dex_for_class(class_name)
        if r is None:
            return None
        cls = self._cls(class_name)
        if cls is None:
            return None
        result = []
        for f in cls.get_fields()[:MAX_FIELD_DISPLAY]:
            access = f.get_access_flags_string() or ""
            if "static" not in access:
                continue
            entry = StaticFieldInfo(
                name=f.get_name(),
                type=f.get_descriptor(),
                init_hex=None,
                init_bytes=None,
                init_label=None,
            )
            iv = f.get_init_value()
            if iv is not None:
                try:
                    if isinstance(iv, list):
                        if len(iv) <= 256:
                            entry.init_hex = bytes(iv).hex()
                            entry.init_bytes = list(iv)
                        else:
                            entry.init_hex = bytes(iv[:64]).hex()
                            entry.init_label = f"byte[{len(iv)}] — truncated"
                    else:
                        entry.init_label = _truncate(str(iv), 100)
                except Exception:
                    entry.init_label = "<error>"
            result.append(entry)
        return result

    # ---- bytecode ----

    def get_bytecode(
        self,
        class_name: str,
        method_name: str,
        method_desc: str = "",
        offset: int = 0,
        limit: int = MAX_BYTECODE_INSTRS,
    ) -> dict[str, Any] | None:
        """Return paginated bytecode for a method."""
        r = self.find_dex_for_class(class_name)
        if r is None:
            return None
        cls = self._cls(class_name)
        if cls is None:
            return None
        for m in cls.get_methods():
            if m.get_name() == method_name:
                if method_desc and m.get_descriptor() != method_desc:
                    continue
                code = m.get_code()
                if code is None:
                    return {
                        "signature": f"{class_name}->{method_name}{m.get_descriptor()}",
                        "access": m.get_access_flags_string(),
                        "total": 0,
                        "offset": 0,
                        "limit": limit,
                        "instructions": [],
                        "note": "no code (abstract/native)",
                    }

                # Collect instructions with offset+limit via islice
                gen = code.get_bc().get_instructions()
                # Skip 'offset' items
                skipped = 0
                for _ in range(offset):
                    try:
                        next(gen)
                        skipped += 1
                    except StopIteration:
                        break

                instrs: list[Instruction] = []
                for i, instr in enumerate(_take_from_generator(limit, gen)):
                    try:
                        show = instr.show(0)
                    except Exception:
                        show = None
                    if show and len(show) > MAX_BYTECODE_SHOW_LEN:
                        show = show[:MAX_BYTECODE_SHOW_LEN] + "…"
                    instrs.append(Instruction(
                        idx=offset + i,
                        op=instr.get_name(),
                        show=show.strip() if show else None,
                    ))

                return {
                    "signature": f"{class_name}->{method_name}{m.get_descriptor()}",
                    "access": m.get_access_flags_string(),
                    "total": None,  # unknown until fully consumed
                    "offset": offset,
                    "limit": limit,
                    "instructions": instrs,
                    "has_more": len(instrs) == limit,
                }
        return None

    # ---- xref ----

    def get_xref(self, method_signature: str) -> XrefResult | None:
        if not self.loaded:
            return None
        parts = method_signature.split("->")
        if len(parts) != 2:
            return None
        class_name, method_part = parts
        m = re.match(r"(.+?)(\(.+)", method_part)
        if not m:
            return None
        m_name, m_desc = m.group(1), m.group(2)
        ma = self.analysis.get_method_analysis_by_name(class_name, m_name, m_desc)
        if not ma:
            return None

        xfrom_items = _take_from_generator(MAX_XREF_COUNT, ma.get_xref_from())
        total_callers = len(xfrom_items)
        xfrom_list = sorted(
            xfrom_items[:MAX_XREF_DISPLAY],
            key=lambda r: f"{r[0].name}->{r[1].name}",
        )

        xto_items = _take_from_generator(MAX_XREF_COUNT, ma.get_xref_to())
        total_callees = len(xto_items)
        xto_list = sorted(
            xto_items[:MAX_XREF_DISPLAY],
            key=lambda r: f"{r[0].name}->{r[1].name}",
        )

        return XrefResult(
            signature=f"{class_name}->{m_name}{m_desc}",
            callers=[
                f"{ref[0].name} -> {ref[1].name}{ref[1].descriptor}"
                for ref in xfrom_list
            ],
            total_callers=total_callers,
            callees=[
                f"{ref[1].name}{ref[1].descriptor} in {ref[0].name}"
                for ref in xto_list
            ],
            total_callees=total_callees,
        )

    # ---- method info ----

    def get_method_info(
        self, class_name: str, method_name: str, method_desc: str = ""
    ) -> MethodInfo | None:
        r = self.find_dex_for_class(class_name)
        if r is None:
            return None
        cls = self._cls(class_name)
        if cls is None:
            return None
        for m in cls.get_methods():
            if m.get_name() == method_name:
                if method_desc and m.get_descriptor() != method_desc:
                    continue
                ma = self.analysis.get_method_analysis_by_name(
                    class_name, method_name, m.get_descriptor()
                )
                code = m.get_code()
                icount = 0
                if code is not None:
                    icount = len(_take_from_generator(
                        MAX_BYTECODE_INSTRS + 1, code.get_bc().get_instructions()
                    ))

                xfrom_items = _take_from_generator(
                    MAX_XREF_COUNT, ma.get_xref_from() if ma else []
                )
                xfrom_items = sorted(xfrom_items, key=lambda r: f"{r[1].name}")
                total_callers = len(xfrom_items)
                callers = [
                    f"{ref[0].name} -> {ref[1].name}{ref[1].descriptor}"
                    for ref in xfrom_items[:MAX_XREF_DISPLAY]
                ]

                xto = ma.get_xref_to() if ma else []
                cc: dict[str, int] = {}
                for ref in _take(200, xto):
                    cn = ref[0].name
                    cc[cn] = cc.get(cn, 0) + 1

                return MethodInfo(
                    signature=f"{class_name}->{method_name}{m.get_descriptor()}",
                    access=m.get_access_flags_string() or "",
                    instr_count=icount,
                    callers=callers,
                    total_callers=total_callers,
                    top_callee_classes=dict(
                        sorted(cc.items(), key=lambda x: -x[1])[:15]
                    ),
                )
        return None

    # ---- manifest ----

    def get_manifest_summary(self) -> ManifestSummary | None:
        if self.apk is None:
            return None
        all_perms = self.apk.get_permissions()
        all_activities = self.apk.get_activities()
        all_services = self.apk.get_services()
        all_receivers = self.apk.get_receivers()

        return ManifestSummary(
            package=self.apk.get_package(),
            version_name=self.apk.get_androidversion_name(),
            version_code=self.apk.get_androidversion_code(),
            min_sdk=self.apk.get_min_sdk_version(),
            target_sdk=self.apk.get_target_sdk_version(),
            app_name=self.apk.get_app_name(),
            permissions=sorted(all_perms)[:MAX_PERMISSIONS],
            total_permissions=len(all_perms),
            activities=sorted(all_activities)[:MAX_ACTIVITIES],
            total_activities=len(all_activities),
            services=sorted(all_services)[:MAX_ACTIVITIES],
            total_services=len(all_services),
            receivers=sorted(all_receivers)[:MAX_ACTIVITIES],
            total_receivers=len(all_receivers),
        )

    # ---- internal helpers ----

    @staticmethod
    def _find_string_index(dx: DEX, target: str) -> int | None:
        for i, s in enumerate(dx.get_strings()):
            if s == target:
                return i
            if i > 500_000:  # safety threshold
                break
        return None


# Singleton instance
analyzer = APKAnalyzer()
