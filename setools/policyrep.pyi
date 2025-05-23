# SPDX-License-Identifier: LGPL-2.1-only
#

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any, NoReturn

import enum
import ipaddress

AnyConstraint = "Constraint" | "Validatetrans"
AnyDefault = "Default" | "DefaultRange"
AnyRBACRule = "RoleAllow" | "RoleTransition"
AnyTERule = "AVRule" | "AVRuleXperm" | "TERule" | "FileNameTERule"
TypeOrAttr = "Type" | "TypeAttribute"

def lookup_boolean_name_sub(name: str) -> str: ...

#
# Policy-wide generic classes, in inheritance order
#

class PolicyObject:
    policy: "SELinuxPolicy" = ...
    def statement(self) -> str: ...
    def __copy__(self) -> "PolicyObject": ...
    def __deepcopy__(self, memo) -> "PolicyObject": ...
    def __eq__(self, other) -> bool: ...
    def __ge__(self, other) -> bool: ...
    def __gt__(self, other) -> bool: ...
    def __hash__(self) -> int: ...
    def __le__(self, other) -> bool: ...
    def __lt__(self, other) -> bool: ...
    def __ne__(self, other) -> bool: ...

class PolicyRule(PolicyObject):
    conditional: "Conditional" = ...
    conditional_block: bool = ...
    extended: bool = ...
    origin: "PolicyRule" = ...
    ruletype: "PolicyEnum" = ...
    source: "PolicySymbol" = ...
    target: "PolicySymbol" = ...
    tclass: "ObjClass" = ...
    xperm_type: str = ...
    perms: frozenset[str] | "XpermSet" = ...
    default: PolicyObject = ...
    filename: str = ...
    def enabled(self, **kwargs) -> bool: ...
    def expand(self) -> Iterable["PolicyRule"]: ...

class PolicySymbol(PolicyObject):
    name: str = ...
    def __contains__(self, other) -> bool: ...
    def expand(self) -> Iterable["PolicySymbol"]: ...

class PolicyEnum(enum.Enum):  # type: ignore[misc]
    @classmethod
    def lookup(cls, value) -> Any: ...

#
# Base classes, in alphabetical order
#

class BaseConstraint(PolicyObject):
    expression: "ConstraintExpression" = ...
    perms: frozenset[str] = ...
    ruletype: "ConstraintRuletype" = ...
    tclass: "ObjClass" = ...

class BaseMLSLevel(PolicyObject):
    sensitivity: "Sensitivity" = ...
    def categories(self) -> Iterable[Category]: ...

class BaseTERule(PolicyRule):
    conditional: "Conditional" = ...
    conditional_block: bool = ...
    filename: str = ...
    ruletype: "TERuletype" = ...
    source: TypeOrAttr = ...
    tclass: "ObjClass" = ...
    target: TypeOrAttr = ...
    def enabled(self, **kwargs) -> bool: ...

class BaseType(PolicySymbol):
    def aliases(self) -> Iterable[str]: ...
    def attributes(self) -> Iterable["BaseType"]: ...
    def expand(self) -> Iterable["BaseType"]: ...

class Ocontext(PolicyObject):
    context: "Context" = ...

#
# Concrete classes, in alphabetical order
#
class AVRule(BaseTERule):
    default: NoReturn = ...
    perms: frozenset[str] = ...
    def derive_expanded(self, *args, **kwargs) -> "AVRule": ...
    def expand(self, *args, **kwargs) -> Iterable["AVRule"]: ...

class AVRuleXperm(BaseTERule):
    default: NoReturn = ...
    perms: "XpermSet" = ...
    xperm_type: str = ...
    def expand(self, *args, **kwargs) -> Iterable["AVRuleXperm"]: ...

class Boolean(PolicySymbol):
    state: bool = ...

class Bounds(PolicyObject):
    child: "Type" = ...
    parent: "Type" = ...
    ruletype: "BoundsRuletype" = ...

class BoundsRuletype(PolicyEnum):
    typebounds = ...

class Category(PolicySymbol):
    def aliases(self, *args, **kwargs) -> Iterable[str]: ...

class Common(PolicySymbol):
    perms: frozenset[str] = ...

class Conditional(PolicyObject):
    booleans: frozenset[Boolean] = ...
    def evaluate(self, **kwargs) -> bool: ...
    def expression(self) -> Iterable["ConditionalOperator" | str]: ...
    def false_rules(self, *args, **kwargs) -> Iterable[AnyTERule]: ...
    def true_rules(self, *args, **kwargs) -> Iterable[AnyTERule]: ...
    def truth_table(self) -> list["TruthTableRow"]: ...
    def __contains__(self, other) -> bool: ...

class ConditionalOperator(PolicyObject):
    evaluate: Callable = ...
    precedence: int = ...
    unary: bool = ...

class Constraint(BaseConstraint):
    perms: frozenset[str] = ...

class ConstraintExprNode(PolicyObject):
    names: frozenset[TypeOrAttr] | frozenset["Role"] | frozenset["User"] = ...
    symbol_type: int = ...
    def __contains__(self, other) -> bool: ...
    def __getitem__(self, index) -> frozenset[TypeOrAttr] | frozenset["Role"] | frozenset["User"] | str: ...
    def __iter__(self) -> Iterable[frozenset[TypeOrAttr] | frozenset["Role"] | frozenset["User"] | str]: ...
    def __len__(self) -> int: ...

class ConstraintExpression(PolicyObject):
    mls: bool = ...
    roles: frozenset["Role"] = ...
    types: frozenset["Type"] = ...
    users: frozenset["User"] = ...
    def infix(self, *args, **kwargs) -> frozenset[TypeOrAttr] | frozenset["Role"] | frozenset["User"] | str: ...
    def __getitem__(self, index) -> frozenset[TypeOrAttr] | frozenset["Role"] | frozenset["User"] | str: ...
    def __iter__(self) -> Iterator[frozenset["Role"] | frozenset["Type"] | frozenset["User"] | str]: ...

class ConstraintRuletype(PolicyEnum):
    constrain = ...
    mlsconstrain = ...
    mlsvalidatetrans = ...
    validatetrans = ...

class Context(PolicyObject):
    range_: "Range" = ...
    role: "Role" = ...
    type_: "Type" = ...
    user: "User" = ...

class Default(PolicyObject):
    default: "DefaultValue" = ...
    ruletype: "DefaultRuletype" = ...
    tclass: "ObjClass" = ...

class DefaultRange(Default):
    default_range: "DefaultRangeValue" = ...

class DefaultRangeValue(PolicyEnum):
    high = ...
    low = ...
    low_high = ...
    @classmethod
    def from_default_range(cls, range: int | None) -> "DefaultRangeValue" | None: ...

class DefaultRuletype(PolicyEnum):
    default_range = ...
    default_role = ...
    default_type = ...
    default_user = ...

class DefaultValue(PolicyEnum):
    glblub = ...
    source = ...
    target = ...
    @classmethod
    def from_default_range(cls, *args, **kwargs) -> "DefaultValue": ...

class Devicetreecon(Ocontext):
    path: str = ...

class FSUse(Ocontext):
    fs: str = ...
    ruletype: "FSUseRuletype" = ...

class FSUseRuletype(PolicyEnum):
    fs_use_task = ...
    fs_use_trans = ...
    fs_use_xattr = ...

class FileNameTERule(BaseTERule):
    default: "Type" = ...
    filename: str = ...
    perms: NoReturn = ...
    ruletype: "TERuletype" = ...
    source: TypeOrAttr = ...
    tclass: "ObjClass" = ...
    target: TypeOrAttr = ...
    def expand(self, *args, **kwargs) -> Iterable["FileNameTERule"]: ...

class GenfsFiletype(int): ...

class Genfscon(Ocontext):
    filetype: "GenfsFiletype" = ...
    fs: str = ...
    path: str = ...
    tclass: "ObjClass" = ...

class HandleUnknown(PolicyEnum):
    allow = ...
    deny = ...
    reject = ...

class Ibendportcon(Ocontext):
    name: str = ...
    port: int = ...

class Ibpkeycon(Ocontext):
    pkeys: "IbpkeyconRange" = ...
    subnet_prefix: ipaddress.IPv6Address = ...

@dataclass(eq=True, order=True, frozen=True)
class IbpkeyconRange:
    high: int = ...
    low: int = ...

class InitialSID(Ocontext):
    name: str = ...

class XpermSet(frozenset[int]):
    def ranges(self) -> int: ...

class IoctlSet(XpermSet): ...

class Iomemcon(Ocontext):
    addr: "IomemconRange" = ...

@dataclass(eq=True, order=True, frozen=True)
class IomemconRange:
    high: int = ...
    low: int = ...

class Ioportcon(Ocontext):
    ports: "IoportconRange" = ...

@dataclass(eq=True, order=True, frozen=True)
class IoportconRange:
    high: int = ...
    low: int = ...

class Level(BaseMLSLevel):
    def __rxor__(self, other) -> bool: ...
    def __xor__(self, other) -> bool: ...

class LevelDecl(BaseMLSLevel): ...

class MLSRule(PolicyRule):
    default: "Range" = ...
    origin: "MLSRule" = ...
    ruletype: "MLSRuletype" = ...
    source: TypeOrAttr = ...
    tclass: "ObjClass" = ...
    target: TypeOrAttr = ...
    def expand(self) -> Iterable["MLSRule"]: ...

class MLSRuletype(PolicyEnum):
    range_transition = ...

class Netifcon(Ocontext):
    netif: str = ...
    packet: "Context" = ...

class Nodecon(Ocontext):
    ip_version: "NodeconIPVersion" = ...
    network: ipaddress.IPv4Network | ipaddress.IPv6Network = ...

class NodeconIPVersion(PolicyEnum):
    ipv4 = ...
    ipv6 = ...

class ObjClass(PolicySymbol):
    common: "Common" = ...
    perms: frozenset[str] = ...
    def constraints(self, *args, **kwargs) -> Iterable["Constraint"]: ...
    def defaults(self, *args, **kwargs) -> Iterable[AnyDefault]: ...
    def validatetrans(self, *args, **kwargs) -> Iterable["Validatetrans"]: ...

class Pcidevicecon(Ocontext):
    device: str = ...

class Pirqcon(Ocontext):
    irq: int = ...

class PolicyCapability(PolicySymbol): ...

class PolicyTarget(PolicyEnum):
    selinux = ...
    xen = ...

class Portcon(Ocontext):
    ports: "PortconRange" = ...
    protocol: "PortconProtocol" = ...

class PortconProtocol(PolicyEnum):
    dccp = ...
    sctp = ...
    tcp = ...
    udp = ...

@dataclass(eq=True, order=True, frozen=True)
class PortconRange:
    high: int = ...
    low: int = ...

class RBACRuletype(PolicyEnum):
    allow = ...
    role_transition = ...

class Range(PolicyObject):
    high: Level = ...
    low: Level = ...
    def __contains__(self, other) -> bool: ...

class Role(PolicySymbol):
    dominated_roles: frozenset["Role"] = ...
    def expand(self) -> Iterable["Role"]: ...
    def types(self) -> Iterable["Type"]: ...

class RoleAllow(PolicyRule):
    default: NoReturn = ...
    ruletype: "RBACRuletype" = ...
    source: "Role" = ...
    tclass: NoReturn = ...
    target: "Role" = ...
    def expand(self) -> Iterable["RoleAllow"]: ...

class RoleTransition(PolicyRule):
    default: "Role" = ...
    ruletype: "RBACRuletype" = ...
    source: "Role" = ...
    tclass: "ObjClass" = ...
    target: TypeOrAttr = ...
    def expand(self) -> Iterable["RoleTransition"]: ...

class SELinuxPolicy:
    allow_count: int = ...
    allowxperm_count: int = ...
    auditallow_count: int = ...
    auditallowxperm_count: int = ...
    boolean_count: int = ...
    category_count: int = ...
    class_count: int = ...
    common_count: int = ...
    conditional_count: int = ...
    constraint_count: int = ...
    default_count: int = ...
    devicetreecon_count: int = ...
    dontaudit_count: int = ...
    dontauditxperm_count: int = ...
    fs_use_count: int = ...
    genfscon_count: int = ...
    handle_unknown: "HandleUnknown" = ...
    ibendportcon_count: int = ...
    ibpkeycon_count: int = ...
    initialsids_count: int = ...
    iomemcon_count: int = ...
    ioportcon_count: int = ...
    level_count: int = ...
    mls: bool = ...
    mlsconstraint_count: int = ...
    mlsvalidatetrans_count: int = ...
    netifcon_count: int = ...
    neverallow_count: int = ...
    neverallowxperm_count: int = ...
    nodecon_count: int = ...
    path: str = ...
    pcidevicecon_count: int = ...
    permission_count: int = ...
    permissives_count: int = ...
    pirqcon_count: int = ...
    polcap_count: int = ...
    portcon_count: int = ...
    range_transition_count: int = ...
    role_allow_count: int = ...
    role_count: int = ...
    role_transition_count: int = ...
    target_platform: "PolicyTarget" = ...
    type_attribute_count: int = ...
    type_change_count: int = ...
    type_count: int = ...
    type_member_count: int = ...
    type_transition_count: int = ...
    typebounds_count: int = ...
    user_count: int = ...
    validatetrans_count: int = ...
    version: int = ...
    def __init__(self, policyfile: str | None = None) -> None: ...
    def bools(self) -> Iterable["Boolean"]: ...
    def bounds(self) -> Iterable["Bounds"]: ...
    def categories(self) -> Iterable["Category"]: ...
    def classes(self) -> Iterable["ObjClass"]: ...
    def commons(self) -> Iterable["Common"]: ...
    def conditionals(self) -> Iterable["Conditional"]: ...
    def constraints(self) -> Iterable[AnyConstraint]: ...
    def defaults(self) -> Iterable[AnyDefault]: ...
    def devicetreecons(self) -> Iterable["Devicetreecon"]: ...
    def fs_uses(self) -> Iterable["FSUse"]: ...
    def genfscons(self) -> Iterable["Genfscon"]: ...
    def ibendportcons(self) -> Iterable["Ibendportcon"]: ...
    def ibpkeycons(self) -> Iterable["Ibpkeycon"]: ...
    def initialsids(self) -> Iterable["InitialSID"]: ...
    def iomemcons(self) -> Iterable["Iomemcon"]: ...
    def ioportcons(self) -> Iterable["Ioportcon"]: ...
    def levels(self) -> Iterable["Level"]: ...
    def lookup_boolean(self, name: "Boolean" | str) -> "Boolean": ...
    def lookup_category(self, name: "Category" | str, deref: bool = True) -> "Category": ...
    def lookup_class(self, name: "ObjClass" | str) -> "ObjClass": ...
    def lookup_common(self, name: "Common" | str) -> "Common": ...
    def lookup_initialsid(self, name: "InitialSID" | str) -> "InitialSID": ...
    def lookup_level(self, name: "Level" | str) -> "Level": ...
    def lookup_range(self, name: "Range" | str) -> "Range": ...
    def lookup_role(self, name: "Role" | str) -> Role: ...
    def lookup_sensitivity(self, name: "Sensitivity" | str) -> "Sensitivity": ...
    def lookup_type(self, name: "Type" | str, deref: bool = True) -> "Type": ...
    def lookup_type_or_attr(self, name: TypeOrAttr | str, deref: bool = True) -> TypeOrAttr: ...
    def lookup_typeattr(self, name: "TypeAttribute" | str) -> "TypeAttribute": ...
    def lookup_user(self, name: "User" | str) -> "User": ...
    def mlsrules(self) -> Iterable["MLSRule"]: ...
    def netifcons(self) -> Iterable["Netifcon"]: ...
    def nodecons(self) -> Iterable["Nodecon"]: ...
    def pcidevicecons(self) -> Iterable["Pcidevicecon"]: ...
    def pirqcons(self) -> Iterable["Pirqcon"]: ...
    def polcaps(self) -> Iterable["PolicyCapability"]: ...
    def portcons(self) -> Iterable["Portcon"]: ...
    def rbacrules(self) -> Iterable[AnyRBACRule]: ...
    def roles(self) -> Iterable["Role"]: ...
    def sensitivities(self) -> Iterable["Sensitivity"]: ...
    def terules(self) -> Iterable[AnyTERule]: ...
    def typeattributes(self) -> Iterable["TypeAttribute"]: ...
    def types(self) -> Iterable["Type"]: ...
    def users(self) -> Iterable["User"]: ...
    def __copy__(self) -> "SELinuxPolicy": ...
    def __deepcopy__(self, memo) -> "SELinuxPolicy": ...

class Sensitivity(PolicySymbol):
    def aliases(self, *args, **kwargs) -> Any: ...
    def level_decl(self, *args, **kwargs) -> Any: ...

class TERule(BaseTERule):
    default: "Type" = ...
    perms: NoReturn = ...
    def expand(self) -> Iterable["TERule"]: ...

class TERuletype(PolicyEnum):
    allow = ...
    allowxperm = ...
    auditallow = ...
    auditallowxperm = ...
    dontaudit = ...
    dontauditxperm = ...
    neverallow = ...
    neverallowxperm = ...
    type_change = ...
    type_member = ...
    type_transition = ...

@dataclass
class TruthTableRow:
    values: dict[str, bool]
    result: bool

class Type(BaseType):
    ispermissive: bool = ...
    def aliases(self) -> Iterable[str]: ...
    def attributes(self) -> Iterable["TypeAttribute"]: ...
    def expand(self) -> Iterable["Type"]: ...

class TypeAttribute(BaseType):
    ispermissive: bool = ...
    def aliases(self) -> Iterable[str]: ...
    def attributes(self) -> Iterable["TypeAttribute"]: ...
    def expand(self) -> Iterable["Type"]: ...
    def __iter__(self) -> Iterable["TypeAttribute"]: ...
    def __len__(self) -> int: ...

class User(PolicySymbol):
    mls_level: "Level" = ...
    mls_range: "Range" = ...
    roles: frozenset["Role"] = ...

class Validatetrans(BaseConstraint):
    perms: NoReturn = ...
