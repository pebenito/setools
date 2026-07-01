# SPDX-License-Identifier: GPL-2.0-only
#
import pytest
import setools


@pytest.mark.obj_args("tests/library/policyrep/selinuxpolicy.conf")
class TestFileContexts:

    """Tests for FileContexts class."""

    def test_lookup_any(self, compiled_policy):
        """FileContexts: lookup with default (any) filetype."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/var/run/test7")
        assert "user0:role0:type7:s0:c0" == str(ctx)

    def test_lookup_file(self, compiled_policy):
        """FileContexts: lookup with regular file type."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/usr/bin/test0", setools.FileContextsFiletype.file)
        assert "user0:role0:type0:s0:c0" == str(ctx)

    def test_lookup_dir(self, compiled_policy):
        """FileContexts: lookup with directory type."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/usr/lib/test1", setools.FileContextsFiletype.dir)
        assert "user0:role0:type1:s0:c0" == str(ctx)

    def test_lookup_chr_file(self, compiled_policy):
        """FileContexts: lookup with character device type."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/usr/sbin/test2", setools.FileContextsFiletype.chr_file)
        assert "user0:role0:type2:s0:c0" == str(ctx)

    def test_lookup_blk_file(self, compiled_policy):
        """FileContexts: lookup with block device type."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/usr/share/test3", setools.FileContextsFiletype.blk_file)
        assert "user0:role0:type3:s0:c0" == str(ctx)

    def test_lookup_sock_file(self, compiled_policy):
        """FileContexts: lookup with socket type."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/usr/local/test4", setools.FileContextsFiletype.sock_file)
        assert "user0:role0:type4:s0:c0" == str(ctx)

    def test_lookup_fifo_file(self, compiled_policy):
        """FileContexts: lookup with named pipe type."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/usr/local/test5", setools.FileContextsFiletype.fifo_file)
        assert "user0:role0:type5:s0:c0" == str(ctx)

    def test_lookup_lnk_file(self, compiled_policy):
        """FileContexts: lookup with symbolic link type."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/usr/local/test6", setools.FileContextsFiletype.lnk_file)
        assert "user0:role0:type6:s0:c0" == str(ctx)

    def test_lookup_regex(self, compiled_policy):
        """FileContexts: lookup with regex path."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/opt/test_regex/subdir/file")
        assert "user0:role0:type8:s0:c0" == str(ctx)

    def test_lookup_no_match(self, compiled_policy):
        """FileContexts: lookup raises NoFileContextsMatch for unmatched path."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        with pytest.raises(setools.exception.NoFileContextsMatch):
            fc.lookup("/nonexistent/path/that/does/not/match")

    def test_path_attribute(self, compiled_policy):
        """FileContexts: path attribute is set correctly."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        assert fc.path == "tests/library/policyrep/file_contexts"

    def test_policy_attribute(self, compiled_policy):
        """FileContexts: policy attribute is set correctly."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        assert fc.policy is compiled_policy

    def test_context_user(self, compiled_policy):
        """FileContexts: returned context has correct user."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/var/run/test7")
        assert isinstance(ctx, setools.Context)
        assert "user0" == str(ctx.user)

    def test_context_role(self, compiled_policy):
        """FileContexts: returned context has correct role."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/var/run/test7")
        assert isinstance(ctx, setools.Context)
        assert "role0" == str(ctx.role)

    def test_context_type(self, compiled_policy):
        """FileContexts: returned context has correct type."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/var/run/test7")
        assert isinstance(ctx, setools.Context)
        assert "type7" == str(ctx.type_)

    def test_context_range(self, compiled_policy):
        """FileContexts: returned context has correct MLS range."""
        fc = setools.FileContexts(compiled_policy, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/var/run/test7")
        assert isinstance(ctx, setools.Context)
        assert "s0:c0" == str(ctx.range_)

    def test_open_nonexistent_file(self, compiled_policy):
        """FileContexts: OSError raised for nonexistent file_contexts path."""
        with pytest.raises(OSError):
            setools.FileContexts(compiled_policy, "/nonexistent/path/file_contexts")


class TestFileContextsNoPolicy:

    """Tests for FileContexts when no policy is provided."""

    def test_attribute(self):
        """FileContexts: policy attribute is None when no policy provided."""
        fc = setools.FileContexts(None, "tests/library/policyrep/file_contexts")
        assert fc.policy is None

    def test_lookup(self):
        """FileContexts: lookup returns raw string when policy is None."""
        fc = setools.FileContexts(None, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/var/run/test7")
        assert ctx == "user0:role0:type7:s0:c0"
        assert isinstance(ctx, str)

    def test_lookup_file(self):
        """FileContexts: lookup with filetype returns raw string when policy is None."""
        fc = setools.FileContexts(None, "tests/library/policyrep/file_contexts")
        ctx = fc.lookup("/usr/bin/test0", setools.FileContextsFiletype.file)
        assert ctx == "user0:role0:type0:s0:c0"
        assert isinstance(ctx, str)

    def test_lookup_no_match(self):
        """FileContexts: lookup raises NoFileContextsMatch when policy is None."""
        fc = setools.FileContexts(None, "tests/library/policyrep/file_contexts")
        with pytest.raises(setools.exception.NoFileContextsMatch):
            fc.lookup("/nonexistent/path/that/does/not/match")
