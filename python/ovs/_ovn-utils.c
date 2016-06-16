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
#include "ovn/lib/actions.h"
#include "ovn/lib/expr.h"
#include "ovn/lib/lex.h"
#include "shash.h"


void initovn_utils(void);

static char parse_match_docs[] =
    "Specify match string to validate\n";

static PyObject* parse_match(PyObject* self OVS_UNUSED, PyObject *args)
{
    char *match_string;
    PyObject *error_string;

    if (!PyArg_ParseTuple(args, "s", &match_string)) {
		return Py_BuildValue("s", "Unable to parse input");
    }

    struct shash symtab;
    create_symtab(&symtab);
    struct expr *expr;
    char *error;
    expr = expr_parse_string(match_string, &symtab, &error);

    expr_destroy(expr);
    expr_symtab_destroy(&symtab);
    shash_destroy(&symtab);
    if(error) {
      error_string = PyString_FromString(error);
      free(error);
		return error_string;
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
