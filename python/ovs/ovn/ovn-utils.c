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


static void
create_symtab(struct shash *symtab)
{
    shash_init(symtab);

    /* Reserve a pair of registers for the logical inport and outport.  A full
     * 32-bit register each is bigger than we need, but the expression code
     * doesn't yet support string fields that occupy less than a full OXM. */
    expr_symtab_add_string(symtab, "inport", MFF_REG6, NULL);
    expr_symtab_add_string(symtab, "outport", MFF_REG7, NULL);

    expr_symtab_add_field(symtab, "xreg0", MFF_XREG0, NULL, false);
    expr_symtab_add_field(symtab, "xreg1", MFF_XREG1, NULL, false);
    expr_symtab_add_field(symtab, "xreg2", MFF_XREG2, NULL, false);

    expr_symtab_add_subfield(symtab, "reg0", NULL, "xreg0[32..63]");
    expr_symtab_add_subfield(symtab, "reg1", NULL, "xreg0[0..31]");
    expr_symtab_add_subfield(symtab, "reg2", NULL, "xreg1[32..63]");
    expr_symtab_add_subfield(symtab, "reg3", NULL, "xreg1[0..31]");
    expr_symtab_add_subfield(symtab, "reg4", NULL, "xreg2[32..63]");
    expr_symtab_add_subfield(symtab, "reg5", NULL, "xreg2[0..31]");

    expr_symtab_add_field(symtab, "eth.src", MFF_ETH_SRC, NULL, false);
    expr_symtab_add_field(symtab, "eth.dst", MFF_ETH_DST, NULL, false);
    expr_symtab_add_field(symtab, "eth.type", MFF_ETH_TYPE, NULL, true);

    expr_symtab_add_field(symtab, "vlan.tci", MFF_VLAN_TCI, NULL, false);
    expr_symtab_add_predicate(symtab, "vlan.present", "vlan.tci[12]");
    expr_symtab_add_subfield(symtab, "vlan.pcp", "vlan.present",
                             "vlan.tci[13..15]");
    expr_symtab_add_subfield(symtab, "vlan.vid", "vlan.present",
                             "vlan.tci[0..11]");

    expr_symtab_add_predicate(symtab, "ip4", "eth.type == 0x800");
    expr_symtab_add_predicate(symtab, "ip6", "eth.type == 0x86dd");
    expr_symtab_add_predicate(symtab, "ip", "ip4 || ip6");
    expr_symtab_add_field(symtab, "ip.proto", MFF_IP_PROTO, "ip", true);
    expr_symtab_add_field(symtab, "ip.dscp", MFF_IP_DSCP, "ip", false);
    expr_symtab_add_field(symtab, "ip.ecn", MFF_IP_ECN, "ip", false);
    expr_symtab_add_field(symtab, "ip.ttl", MFF_IP_TTL, "ip", false);

    expr_symtab_add_field(symtab, "ip4.src", MFF_IPV4_SRC, "ip4", false);
    expr_symtab_add_field(symtab, "ip4.dst", MFF_IPV4_DST, "ip4", false);

    expr_symtab_add_predicate(symtab, "icmp4", "ip4 && ip.proto == 1");
    expr_symtab_add_field(symtab, "icmp4.type", MFF_ICMPV4_TYPE, "icmp4",
              false);
    expr_symtab_add_field(symtab, "icmp4.code", MFF_ICMPV4_CODE, "icmp4",
              false);

    expr_symtab_add_field(symtab, "ip6.src", MFF_IPV6_SRC, "ip6", false);
    expr_symtab_add_field(symtab, "ip6.dst", MFF_IPV6_DST, "ip6", false);
    expr_symtab_add_field(symtab, "ip6.label", MFF_IPV6_LABEL, "ip6", false);

    expr_symtab_add_predicate(symtab, "icmp6", "ip6 && ip.proto == 58");
    expr_symtab_add_field(symtab, "icmp6.type", MFF_ICMPV6_TYPE, "icmp6",
                          true);
    expr_symtab_add_field(symtab, "icmp6.code", MFF_ICMPV6_CODE, "icmp6",
                          true);

    expr_symtab_add_predicate(symtab, "icmp", "icmp4 || icmp6");

    expr_symtab_add_field(symtab, "ip.frag", MFF_IP_FRAG, "ip", false);
    expr_symtab_add_predicate(symtab, "ip.is_frag", "ip.frag[0]");
    expr_symtab_add_predicate(symtab, "ip.later_frag", "ip.frag[1]");
    expr_symtab_add_predicate(symtab, "ip.first_frag", "ip.is_frag && !ip.later_frag");

    expr_symtab_add_predicate(symtab, "arp", "eth.type == 0x806");
    expr_symtab_add_field(symtab, "arp.op", MFF_ARP_OP, "arp", false);
    expr_symtab_add_field(symtab, "arp.spa", MFF_ARP_SPA, "arp", false);
    expr_symtab_add_field(symtab, "arp.sha", MFF_ARP_SHA, "arp", false);
    expr_symtab_add_field(symtab, "arp.tpa", MFF_ARP_TPA, "arp", false);
    expr_symtab_add_field(symtab, "arp.tha", MFF_ARP_THA, "arp", false);

    expr_symtab_add_predicate(symtab, "nd", "icmp6.type == {135, 136} && icmp6.code == 0");
    expr_symtab_add_field(symtab, "nd.target", MFF_ND_TARGET, "nd", false);
    expr_symtab_add_field(symtab, "nd.sll", MFF_ND_SLL,
              "nd && icmp6.type == 135", false);
    expr_symtab_add_field(symtab, "nd.tll", MFF_ND_TLL,
              "nd && icmp6.type == 136", false);

    expr_symtab_add_predicate(symtab, "tcp", "ip.proto == 6");
    expr_symtab_add_field(symtab, "tcp.src", MFF_TCP_SRC, "tcp", false);
    expr_symtab_add_field(symtab, "tcp.dst", MFF_TCP_DST, "tcp", false);
    expr_symtab_add_field(symtab, "tcp.flags", MFF_TCP_FLAGS, "tcp", false);

    expr_symtab_add_predicate(symtab, "udp", "ip.proto == 17");
    expr_symtab_add_field(symtab, "udp.src", MFF_UDP_SRC, "udp", false);
    expr_symtab_add_field(symtab, "udp.dst", MFF_UDP_DST, "udp", false);

    expr_symtab_add_predicate(symtab, "sctp", "ip.proto == 132");
    expr_symtab_add_field(symtab, "sctp.src", MFF_SCTP_SRC, "sctp", false);
    expr_symtab_add_field(symtab, "sctp.dst", MFF_SCTP_DST, "sctp", false);

    /* For negative testing. */
    expr_symtab_add_field(symtab, "bad_prereq", MFF_XREG0, "xyzzy", false);
    expr_symtab_add_field(symtab, "self_recurse", MFF_XREG0,
                          "self_recurse != 0", false);
    expr_symtab_add_field(symtab, "mutual_recurse_1", MFF_XREG0,
                          "mutual_recurse_2 != 0", false);
    expr_symtab_add_field(symtab, "mutual_recurse_2", MFF_XREG0,
                          "mutual_recurse_1 != 0", false);
    expr_symtab_add_string(symtab, "big_string", MFF_XREG0, NULL);
}


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
    Py_InitModule3("ovn_utils", ovn_utils_funcs,
                   "Extension module example!");
}
