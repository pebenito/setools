# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

from cpython.exc cimport PyErr_SetFromErrnoWithFilename
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from libc.errno cimport errno, EPERM, ENOENT, ENOMEM, EINVAL
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, uintptr_t
from libc.stdio cimport FILE, fopen, fclose, snprintf
from libc.stdlib cimport calloc, free
from libc.string cimport memcpy, memset, strerror

import dataclasses
import logging
import warnings
import itertools
import ipaddress
import collections
import enum
import weakref
from typing import TypeVar, Union

cimport sepol
cimport selinux

from .exception import *

cdef extern from "<stdio.h>":
    int vasprintf(char **strp, const char *fmt, va_list ap)

cdef extern from "<stdarg.h>":
    ctypedef struct va_list:
        pass
    void va_start(va_list, void* arg)
    void va_end(va_list)

cdef extern from "<sys/socket.h>":
    ctypedef unsigned int socklen_t
    enum:
        AF_INET
        AF_INET6

cdef extern from "<netinet/in.h>":
    enum:
        INET6_ADDRSTRLEN
        IPPROTO_DCCP
        IPPROTO_SCTP
        IPPROTO_TCP
        IPPROTO_UDP

cdef extern from "<sys/stat.h>":
    enum:
        S_IFBLK
        S_IFCHR
        S_IFDIR
        S_IFIFO
        S_IFREG
        S_IFLNK
        S_IFSOCK

cdef extern from "<arpa/inet.h>":
    cdef const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)

# this must be here so that the PolicyEnum subclasses are created correctly.
# otherwise you get an error during runtime
include "util.pxi"

include "boolcond.pxi"
include "bounds.pxi"
include "constraint.pxi"
include "context.pxi"
include "default.pxi"
include "filecontexts.pxi"
include "fscontext.pxi"
include "initsid.pxi"
include "mls.pxi"
include "mlsrule.pxi"
include "netcontext.pxi"
include "objclass.pxi"
include "object.pxi"
include "polcap.pxi"
include "rbacrule.pxi"
include "role.pxi"
include "rule.pxi"
include "selinuxpolicy.pxi"
include "terule.pxi"
include "typeattr.pxi"
include "user.pxi"
include "xencontext.pxi"
