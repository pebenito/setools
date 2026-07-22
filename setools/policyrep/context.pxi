# Copyright 2014-2015, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

cdef class Context(PolicyObject):

    """A SELinux security context/security attribute."""

    cdef:
        readonly User user
        readonly Role role
        readonly Type type_
        Range _range

    @staticmethod
    cdef inline Context factory(SELinuxPolicy policy, sepol.context_struct_t *symbol):
        """Factory function for creating Context objects."""
        cdef Context c = Context.__new__(Context)
        c.policy = policy
        c.key = <uintptr_t>symbol
        c.user = User.factory(policy, policy.user_value_to_datum(symbol.user - 1))
        c.role = Role.factory(policy, policy.role_value_to_datum(symbol.role - 1))
        c.type_ = Type.factory(policy, policy.type_value_to_datum(symbol.type - 1))

        if policy.mls:
            c._range = Range.factory(policy, &symbol.range)

        return c

    @staticmethod
    cdef inline Context factory_from_string(SELinuxPolicy policy, str ctx):
        """Factory function for creating Context objects from a string."""
        cdef:
            Context c = Context.__new__(Context)
            list items = ctx.split(":", maxsplit=3)

        try:
            c.user = policy.lookup_user(items[0])
            c.role = policy.lookup_role(items[1])
            c.type_ = policy.lookup_type(items[2])

            # object_r is a special case: it is implicitly associated with
            # all users and types.
            if c.role != "object_r":
                if c.role not in c.user.roles:
                    raise InvalidContext(
                        f"{ctx} is invalid: Role {c.role} is not associated to user {c.user}.")
                if c.type_ not in tuple(c.role.types()):
                    raise InvalidContext(
                        f"{ctx} is invalid: Type {c.type_} is not associated to role {c.role}.")

            if policy.mls:
                c._range = policy.lookup_range(items[3])
                if not c._range <= c.user.mls_range:
                    raise InvalidContext(
                        f"{ctx} is invalid: Range {c._range} not in user {c.user}'s "
                        f"allowed range {c.user.mls_range}")

            c.policy = policy
            return c

        except IndexError as ex:
            raise InvalidContext("f{ctx} is invalid: Context is incomplete.") from ex

        except InvalidSymbol as ex:
            raise InvalidContext(f"{ctx} is invalid: {ex}") from ex

    def __str__(self):
        if self._range:
            return f"{self.user}:{self.role}:{self.type_}:{self.range_}"
        else:
            return f"{self.user}:{self.role}:{self.type_}"

    @property
    def range_(self):
        """The MLS range of the context."""
        if self._range:
            return self._range
        else:
            raise MLSDisabled

    def statement(self):
        raise NoStatement
