#ifndef RAYFW_UAPI_H
#define RAYFW_UAPI_H

#include <linux/types.h>

#define RAYFW_GENL_NAME "rayfw"
#define RAYFW_GENL_VERSION 1
#define RAYFW_API_VERSION 1
#define RAYFW_IFNAME_LEN 16

enum rayfw_command {
	RAYFW_CMD_UNSPEC,
	RAYFW_CMD_ADD_RULE,
	RAYFW_CMD_DELETE_RULE,
	RAYFW_CMD_FLUSH_RULES,
	RAYFW_CMD_SET_POLICY,
	RAYFW_CMD_SET_ENABLED,
	RAYFW_CMD_GET_STATUS,
	RAYFW_CMD_LIST_RULES,
	RAYFW_CMD_RESET_COUNTERS,
	RAYFW_CMD_TX_BEGIN,
	RAYFW_CMD_TX_COMMIT,
	RAYFW_CMD_TX_ABORT,
	__RAYFW_CMD_MAX,
};
#define RAYFW_CMD_MAX (__RAYFW_CMD_MAX - 1)

enum rayfw_attribute {
	RAYFW_A_UNSPEC,
	RAYFW_A_RULE,
	RAYFW_A_RULE_ID,
	RAYFW_A_CHAIN,
	RAYFW_A_POLICY,
	RAYFW_A_ENABLED,
	RAYFW_A_VERSION,
	RAYFW_A_RULE_COUNT,
	RAYFW_A_POLICY_INPUT,
	RAYFW_A_POLICY_OUTPUT,
	RAYFW_A_POLICY_FORWARD,
	RAYFW_A_TX_ID,
	__RAYFW_A_MAX,
};
#define RAYFW_A_MAX (__RAYFW_A_MAX - 1)

enum rayfw_chain {
	RAYFW_CHAIN_INPUT,
	RAYFW_CHAIN_OUTPUT,
	RAYFW_CHAIN_FORWARD,
	RAYFW_CHAIN_MAX,
	RAYFW_CHAIN_ALL = 255,
};

enum rayfw_family {
	RAYFW_FAMILY_ANY,
	RAYFW_FAMILY_IPV4 = 4,
	RAYFW_FAMILY_IPV6 = 6,
};

enum rayfw_protocol {
	RAYFW_PROTO_ANY,
	RAYFW_PROTO_ICMP = 1,
	RAYFW_PROTO_TCP = 6,
	RAYFW_PROTO_UDP = 17,
	RAYFW_PROTO_ICMPV6 = 58,
};

enum rayfw_action {
	RAYFW_ACTION_ACCEPT,
	RAYFW_ACTION_DROP,
};

enum rayfw_policy {
	RAYFW_POLICY_ACCEPT,
	RAYFW_POLICY_DROP,
};

enum rayfw_rule_flags {
	RAYFW_RULE_F_LOG = 1U << 0,
	RAYFW_RULE_F_SRC = 1U << 1,
	RAYFW_RULE_F_DST = 1U << 2,
	RAYFW_RULE_F_SPORT = 1U << 3,
	RAYFW_RULE_F_DPORT = 1U << 4,
	RAYFW_RULE_F_IN_IF = 1U << 5,
	RAYFW_RULE_F_OUT_IF = 1U << 6,
	RAYFW_RULE_F_CT_STATE = 1U << 7,
};

enum rayfw_ct_state {
	RAYFW_CT_NEW = 1U << 0,
	RAYFW_CT_ESTABLISHED = 1U << 1,
	RAYFW_CT_RELATED = 1U << 2,
	RAYFW_CT_INVALID = 1U << 3,
	RAYFW_CT_UNTRACKED = 1U << 4,
};

/* Native-endian ABI shared only between the running kernel and local CLI. */
struct rayfw_rule_wire {
	__u16 api_version;
	__u16 struct_size;
	__u32 id;
	__s32 priority;
	__u8 chain;
	__u8 family;
	__u8 protocol;
	__u8 action;
	__u8 src_prefix;
	__u8 dst_prefix;
	__u16 flags;
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u16 src_port_from;
	__u16 src_port_to;
	__u16 dst_port_from;
	__u16 dst_port_to;
	__u32 ct_states;
	char in_ifname[RAYFW_IFNAME_LEN];
	char out_ifname[RAYFW_IFNAME_LEN];
	__u64 packets;
	__u64 bytes;
};

#endif
