/*
 * Copyright (c) 2013, 2021
 *	The Tcpdump Group and contributors.  All rights reserved.
 * Originally derived (via tcpdump) from FreeRADIUS server source code with
 * permission.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef tcpslice_diag_control_h
#define tcpslice_diag_control_h

#include "compiler-tests.h"
#define DIAG_DO_PRAGMA(x) _Pragma (#x)

/*
 * XL C has to be tested first because starting with version 16.1 it defines
 * both __GNUC__ and __clang__.
 */
#if TCPSLICE_IS_AT_LEAST_XL_C_VERSION(1,0)
  /*
   * GCC diagnostic pragmas became available in XL C version 16.1.0, for Linux
   * only. XL C for Linux always defines __linux__.
   */
  #if TCPSLICE_IS_AT_LEAST_XL_C_VERSION(16,1) && defined(__linux__)
    #define DIAG_OFF_PEDANTIC \
      DIAG_DO_PRAGMA(GCC diagnostic push) \
      DIAG_DO_PRAGMA(GCC diagnostic ignored "-Wpedantic")
    #define DIAG_ON_PEDANTIC \
      DIAG_DO_PRAGMA(GCC diagnostic pop)
  #endif
/*
 * Clang defines __GNUC__ and __GNUC_MINOR__, so has to be tested before GCC.
 */
#elif TCPSLICE_IS_AT_LEAST_CLANG_VERSION(2,8)
  #define DIAG_OFF_PEDANTIC \
    DIAG_DO_PRAGMA(clang diagnostic push) \
    DIAG_DO_PRAGMA(clang diagnostic ignored "-Wpedantic")
  #define DIAG_ON_PEDANTIC \
    DIAG_DO_PRAGMA(clang diagnostic pop)
/*
 * GCC 4.6 has working ignored/push/pop.
 */
#elif TCPSLICE_IS_AT_LEAST_GNUC_VERSION(4,6)
  /*
   * -Wpedantic became available in GCC 4.8.0.
   */
  #if TCPSLICE_IS_AT_LEAST_GNUC_VERSION(4,8)
    #define DIAG_OFF_PEDANTIC \
      DIAG_DO_PRAGMA(GCC diagnostic push) \
      DIAG_DO_PRAGMA(GCC diagnostic ignored "-Wpedantic")
    #define DIAG_ON_PEDANTIC \
      DIAG_DO_PRAGMA(GCC diagnostic pop)
  #endif
#endif

#ifndef DIAG_OFF_PEDANTIC
#define DIAG_OFF_PEDANTIC
#endif
#ifndef DIAG_ON_PEDANTIC
#define DIAG_ON_PEDANTIC
#endif

#endif /* tcpslice_diag_control_h */
