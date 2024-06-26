# Copyright 2014-2015, Tresys Technology, LLC
#
# SPDX-License-Identifier: LGPL-2.1-only
#
from collections.abc import Iterable
import re
import typing

from . import exception, mixins, policyrep, query, util
from .descriptors import CriteriaDescriptor, CriteriaSetDescriptor

__all__: typing.Final[tuple[str, ...]] = ("RBACRuleQuery",)


class RBACRuleQuery(mixins.MatchObjClass, query.PolicyQuery):

    """
    Query the RBAC rules.

    Parameter:
    policy            The policy to query.

    Keyword Parameters/Class attributes:
    ruletype        The list of rule type(s) to match.
    source          The name of the source role/attribute to match.
    source_indirect If true, members of an attribute will be
                    matched rather than the attribute itself.
    source_regex    If true, regular expression matching will
                    be used on the source role/attribute.
                    Obeys the source_indirect option.
    target          The name of the target role/attribute to match.
    target_indirect If true, members of an attribute will be
                    matched rather than the attribute itself.
    target_regex    If true, regular expression matching will
                    be used on the target role/attribute.
                    Obeys target_indirect option.
    tclass          The object class(es) to match.
    tclass_regex    If true, use a regular expression for
                    matching the rule's object class.
    default         The name of the default role to match.
    default_regex   If true, regular expression matching will
                    be used on the default role.
    """

    ruletype = CriteriaSetDescriptor[policyrep.RBACRuletype](enum_class=policyrep.RBACRuletype)
    source = CriteriaDescriptor[policyrep.Role]("source_regex", "lookup_role")
    source_regex: bool = False
    source_indirect: bool = True
    _target: re.Pattern[str] | policyrep.Role | policyrep.TypeOrAttr | None = None
    target_regex: bool = False
    target_indirect: bool = True
    tclass = CriteriaSetDescriptor[policyrep.ObjClass]("tclass_regex", "lookup_class")
    tclass_regex: bool = False
    default = CriteriaDescriptor[policyrep.Role]("default_regex", "lookup_role")
    default_regex: bool = False

    @property
    def target(self) -> re.Pattern[str] | policyrep.Role | policyrep.TypeOrAttr | None:
        return self._target

    @target.setter
    def target(self, value: str | policyrep.Role | policyrep.TypeOrAttr | None) -> None:
        if not value:
            self._target = None
        elif self.target_regex:
            self._target = re.compile(str(value))
        else:
            try:
                self._target = self.policy.lookup_type_or_attr(
                    typing.cast(str | policyrep.TypeOrAttr, value))
            except exception.InvalidType:
                self._target = self.policy.lookup_role(
                    typing.cast(str | policyrep.Role, value))

    def results(self) -> Iterable[policyrep.AnyRBACRule]:
        """Generator which yields all matching RBAC rules."""
        self.log.info(f"Generating RBAC rule results from {self.policy}")
        self.log.debug(f"{self.ruletype=}")
        self.log.debug(f"{self.source=}, {self.source_indirect=}, {self.source_regex=}")
        self.log.debug(f"{self.target=}, {self.target_indirect=}, {self.target_regex=}")
        self._match_object_class_debug(self.log)
        self.log.debug(f"{self.default=}, {self.default_regex=}")

        for rule in self.policy.rbacrules():
            #
            # Matching on rule type
            #
            if self.ruletype:
                if rule.ruletype not in self.ruletype:
                    continue

            #
            # Matching on source role
            #
            if self.source and not util.match_indirect_regex(
                    rule.source,
                    self.source,
                    self.source_indirect,
                    self.source_regex):
                continue

            #
            # Matching on target type (role_transition)/role(allow)
            #
            if self.target and not util.match_indirect_regex(
                    rule.target,
                    self.target,
                    self.target_indirect,
                    self.target_regex):
                continue

            #
            # Matching on object class
            #
            try:
                if not self._match_object_class(rule):
                    continue
            except exception.RuleUseError:
                continue

            #
            # Matching on default role
            #
            if self.default:
                try:
                    # because default role is always a single
                    # role, hard-code indirect to True
                    # so the criteria can be an attribute
                    if not util.match_indirect_regex(
                            rule.default,
                            self.default,
                            True,
                            self.default_regex):
                        continue
                except exception.RuleUseError:
                    continue

            # if we get here, we have matched all available criteria
            yield rule
