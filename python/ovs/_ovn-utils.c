/*
 * Copyright (c) 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <Python.h>


#include <config.h>
#include <errno.h>
#include <getopt.h>
#include <sys/wait.h>
#include "command-line.h"
#include "fatal-signal.h"
#include "flow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/thread.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"

#include "ovn/lib/actions.h"
#include "ovn/lib/expr.h"
#include "ovn/lib/lex.h"
#include "ovs-thread.h"
#include "shash.h"
#include "simap.h"
#include "util.h"


void initovn_utils(void);

static char parse_match_docs[] =
    "Specify match string to validate\n";

static PyObject* parse_match(PyObject* self, PyObject *args)
{
    char *string;

    if (!PyArg_ParseTuple(args, "s", &string)) {
		return Py_BuildValue("s", "Unable to parse input");
    }

    struct shash symtab;
    create_symtab(&symtab);
    struct expr *expr;
    char *error;
    expr = expr_parse_string(string, &symtab, &error);

    expr_destroy(expr);
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
    if(error) {
		return Py_BuildValue("s", error);
    }
    Py_RETURN_NONE;
}


static PyMethodDef ovn_utils_funcs[] = {
    {"parse_match", parse_match, METH_VARARGS, parse_match_docs},
    {NULL}
};

void initovn_utils(void)
{
    Py_InitModule3("ovs.ovn_utils", ovn_utils_funcs,
                   "OVN helper utilities");
}
