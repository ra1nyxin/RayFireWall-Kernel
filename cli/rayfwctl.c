// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <uapi/rayfw.h>

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

#define RAYFWCTL_VERSION "0.1.0"
#define NL_BUFFER_SIZE 65536
#define DEFAULT_CONFIG "/etc/rayfw/rules.conf"
#define ROLLBACK_DIR "/run/rayfw"
#define ROLLBACK_MARKER ROLLBACK_DIR "/pending-confirmation"
#define ROLLBACK_MIN_TIMEOUT 10U
#define ROLLBACK_MAX_TIMEOUT 3600U

struct nl_client {
	int fd;
	uint16_t family_id;
	uint32_t seq;
	uint32_t portid;
	uint32_t transaction_id;
};

struct attr_buffer {
	unsigned char data[4096];
	size_t len;
};

typedef int (*message_handler)(struct nlmsghdr *, void *);

static bool json_output;

static void print_help(FILE *out)
{
	fprintf(out,
		"RayFireWall 内核防火墙控制器 %s\n\n"
		"用法: rayfwctl [--json] <命令> [参数]\n\n"
		"命令:\n"
		"  status | 状态                  查看模块状态与默认策略\n"
		"  list | 规则                    列出规则和命中计数\n"
		"  add | 添加 <选项>              添加规则\n"
		"  delete | 删除 <ID>             删除规则\n"
		"  flush | 清空 [链]              清空全部或指定链\n"
		"  policy | 策略 <链> <策略>      设置默认策略\n"
		"  enable | 启用                  启用过滤\n"
		"  disable | 停用                 临时旁路过滤\n"
		"  reset-counters | 计数清零      清零所有规则计数\n"
		"  save | 保存 [文件]             保存当前配置\n"
		"  load | 加载 [--confirm-timeout 秒] [文件]\n"
		"                                  安全恢复配置；可选超时自动旁路\n"
		"  confirm | 确认                  确认保留受保护的配置加载\n"
		"  check | 检查 [文件]            离线检查配置语法\n"
		"  logs | 日志 [-f]               查看内核匹配日志\n"
		"  help | 帮助                    显示帮助\n\n"
		"添加规则选项:\n"
		"  --chain input|output|forward   必填，规则链\n"
		"  --action accept|drop           必填，动作\n"
		"  --family any|ipv4|ipv6         地址族（CIDR 会自动推断）\n"
		"  --proto any|tcp|udp|icmp|icmpv6\n"
		"  --src CIDR       --dst CIDR    源/目标网段\n"
		"  --sport 端口[-端口]            源端口或范围\n"
		"  --dport 端口[-端口]            目标端口或范围\n"
		"  --in 接口         --out 接口   入/出接口\n"
		"  --state 状态[,状态]            new,established,related,invalid,untracked\n"
		"  --priority 数字                 数字越小越先匹配，默认 1000\n"
		"  --log                           限速写入内核日志\n\n"
		"示例:\n"
		"  rayfwctl add --chain input --action accept --proto tcp --dport 22\n"
		"  rayfwctl add --chain input --action drop --src 203.0.113.0/24 --log\n"
		"  rayfwctl load --confirm-timeout 60 /etc/rayfw/rules.conf\n"
		"  rayfwctl confirm\n",
		RAYFWCTL_VERSION);
}

static int attr_add(struct attr_buffer *buf, uint16_t type,
		    const void *data, size_t data_len)
{
	size_t total = NLA_HDRLEN + data_len;
	size_t aligned = NLA_ALIGN(total);
	struct nlattr *attr;

	if (buf->len + aligned > sizeof(buf->data))
		return -EMSGSIZE;
	attr = (struct nlattr *)(buf->data + buf->len);
	attr->nla_type = type;
	attr->nla_len = total;
	memcpy((unsigned char *)attr + NLA_HDRLEN, data, data_len);
	memset((unsigned char *)attr + total, 0, aligned - total);
	buf->len += aligned;
	return 0;
}

static int attr_add_u8(struct attr_buffer *buf, uint16_t type, uint8_t value)
{
	return attr_add(buf, type, &value, sizeof(value));
}

static int attr_add_u32(struct attr_buffer *buf, uint16_t type, uint32_t value)
{
	return attr_add(buf, type, &value, sizeof(value));
}

static int attr_add_transaction(const struct nl_client *client,
				struct attr_buffer *attrs)
{
	if (!client->transaction_id)
		return 0;
	return attr_add_u32(attrs, RAYFW_A_TX_ID, client->transaction_id);
}

static bool attr_ok(const struct nlattr *attr, int remaining)
{
	return remaining >= (int)sizeof(*attr) && attr->nla_len >= sizeof(*attr) &&
	       attr->nla_len <= remaining;
}

static struct nlattr *attr_next(const struct nlattr *attr, int *remaining)
{
	int step = NLA_ALIGN(attr->nla_len);

	*remaining -= step;
	return (struct nlattr *)((unsigned char *)attr + step);
}

static void *attr_data(const struct nlattr *attr)
{
	return (unsigned char *)attr + NLA_HDRLEN;
}

static int attr_payload(const struct nlattr *attr)
{
	return attr->nla_len - NLA_HDRLEN;
}

static void parse_attrs(struct nlattr **table, int max_type,
			struct nlattr *first, int remaining)
{
	memset(table, 0, sizeof(*table) * (max_type + 1));
	while (attr_ok(first, remaining)) {
		int type = first->nla_type & NLA_TYPE_MASK;

		if (type <= max_type)
			table[type] = first;
		first = attr_next(first, &remaining);
	}
}

static int nl_send(struct nl_client *client, uint16_t type, uint8_t command,
		   uint16_t flags, const struct attr_buffer *attrs)
{
	unsigned char request[8192] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)request;
	struct genlmsghdr *genl;
	struct sockaddr_nl peer = { .nl_family = AF_NETLINK };
	size_t base = NLMSG_HDRLEN + GENL_HDRLEN;
	ssize_t sent;

	if (base + attrs->len > sizeof(request))
		return -EMSGSIZE;
	nlh->nlmsg_len = base + attrs->len;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = ++client->seq;
	nlh->nlmsg_pid = client->portid;
	genl = (struct genlmsghdr *)(request + NLMSG_HDRLEN);
	genl->cmd = command;
	genl->version = RAYFW_GENL_VERSION;
	memcpy(request + base, attrs->data, attrs->len);
	sent = sendto(client->fd, request, nlh->nlmsg_len, 0,
		      (struct sockaddr *)&peer, sizeof(peer));
	if (sent < 0)
		return -errno;
	return sent == (ssize_t)nlh->nlmsg_len ? 0 : -EIO;
}

static int nl_receive(struct nl_client *client, bool multipart,
		      message_handler handler, void *context)
{
	unsigned char buffer[NL_BUFFER_SIZE];

	for (;;) {
		ssize_t length = recv(client->fd, buffer, sizeof(buffer), 0);
		struct nlmsghdr *nlh;
		int remaining;

		if (length < 0)
			return -errno;
		remaining = length;
		for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, remaining);
		     nlh = NLMSG_NEXT(nlh, remaining)) {
			if (nlh->nlmsg_seq != client->seq)
				continue;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *error = NLMSG_DATA(nlh);

				return error->error;
			}
			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (handler) {
				int result = handler(nlh, context);

				if (result)
					return result;
			}
			if (!multipart)
				return 0;
		}
	}
}

static int nl_request(struct nl_client *client, uint8_t command,
		      const struct attr_buffer *attrs, bool multipart,
		      bool reply_expected, message_handler handler, void *context)
{
	uint16_t flags = NLM_F_REQUEST;
	int result;

	if (multipart)
		flags |= NLM_F_DUMP;
	else if (!reply_expected)
		flags |= NLM_F_ACK;
	result = nl_send(client, client->family_id, command, flags, attrs);
	if (result)
		return result;
	return nl_receive(client, multipart, handler, context);
}

static int family_handler(struct nlmsghdr *nlh, void *context)
{
	uint16_t *family_id = context;
	struct genlmsghdr *genl = NLMSG_DATA(nlh);
	struct nlattr *table[CTRL_ATTR_MAX + 1];
	int remaining = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
	struct nlattr *first = (struct nlattr *)((unsigned char *)genl + GENL_HDRLEN);

	parse_attrs(table, CTRL_ATTR_MAX, first, remaining);
	if (!table[CTRL_ATTR_FAMILY_ID] ||
	    attr_payload(table[CTRL_ATTR_FAMILY_ID]) < (int)sizeof(*family_id))
		return -EPROTO;
	memcpy(family_id, attr_data(table[CTRL_ATTR_FAMILY_ID]), sizeof(*family_id));
	return 0;
}

static int nl_open_client(struct nl_client *client)
{
	struct sockaddr_nl local = { .nl_family = AF_NETLINK };
	socklen_t local_len = sizeof(local);
	struct attr_buffer attrs = {0};
	int result;

	memset(client, 0, sizeof(*client));
	client->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (client->fd < 0)
		return -errno;
	if (bind(client->fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		result = -errno;
		close(client->fd);
		return result;
	}
	if (getsockname(client->fd, (struct sockaddr *)&local, &local_len) < 0) {
		result = -errno;
		close(client->fd);
		return result;
	}
	client->portid = local.nl_pid;
	result = attr_add(&attrs, CTRL_ATTR_FAMILY_NAME, RAYFW_GENL_NAME,
			  strlen(RAYFW_GENL_NAME) + 1);
	if (!result)
		result = nl_send(client, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
				 NLM_F_REQUEST, &attrs);
	if (!result)
		result = nl_receive(client, false, family_handler, &client->family_id);
	if (result) {
		close(client->fd);
		client->fd = -1;
	}
	return result;
}

static const char *chain_name(uint8_t chain)
{
	static const char *names[] = { "INPUT", "OUTPUT", "FORWARD" };

	return chain < RAYFW_CHAIN_MAX ? names[chain] : "?";
}

static const char *family_name(uint8_t family)
{
	if (family == RAYFW_FAMILY_IPV4)
		return "IPv4";
	if (family == RAYFW_FAMILY_IPV6)
		return "IPv6";
	return "ANY";
}

static const char *protocol_name(uint8_t protocol)
{
	switch (protocol) {
	case RAYFW_PROTO_TCP: return "TCP";
	case RAYFW_PROTO_UDP: return "UDP";
	case RAYFW_PROTO_ICMP: return "ICMP";
	case RAYFW_PROTO_ICMPV6: return "ICMPv6";
	default: return "ANY";
	}
}

static const char *action_name(uint8_t action)
{
	return action == RAYFW_ACTION_DROP ? "DROP" : "ACCEPT";
}

static const char *policy_name(uint8_t policy)
{
	return policy == RAYFW_POLICY_DROP ? "DROP" : "ACCEPT";
}

static int parse_chain(const char *text, uint8_t *chain, bool allow_all)
{
	if (!strcasecmp(text, "input") || !strcmp(text, "入站"))
		*chain = RAYFW_CHAIN_INPUT;
	else if (!strcasecmp(text, "output") || !strcmp(text, "出站"))
		*chain = RAYFW_CHAIN_OUTPUT;
	else if (!strcasecmp(text, "forward") || !strcmp(text, "转发"))
		*chain = RAYFW_CHAIN_FORWARD;
	else if (allow_all && (!strcasecmp(text, "all") || !strcmp(text, "全部")))
		*chain = RAYFW_CHAIN_ALL;
	else
		return -EINVAL;
	return 0;
}

static int parse_policy(const char *text, uint8_t *policy)
{
	if (!strcasecmp(text, "accept") || !strcmp(text, "接受"))
		*policy = RAYFW_POLICY_ACCEPT;
	else if (!strcasecmp(text, "drop") || !strcmp(text, "丢弃"))
		*policy = RAYFW_POLICY_DROP;
	else
		return -EINVAL;
	return 0;
}

static int parse_u32(const char *text, uint32_t *value)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || *text == '\0' || *end != '\0' || parsed > UINT32_MAX)
		return -EINVAL;
	*value = parsed;
	return 0;
}

static int parse_priority(const char *text, int32_t *value)
{
	char *end;
	long parsed;

	errno = 0;
	parsed = strtol(text, &end, 10);
	if (errno || *text == '\0' || *end != '\0' || parsed < INT32_MIN ||
	    parsed > INT32_MAX)
		return -EINVAL;
	*value = parsed;
	return 0;
}

static int parse_port_range(const char *text, uint16_t *from, uint16_t *to)
{
	char copy[32];
	char *dash;
	uint32_t first, last;

	if (strlen(text) >= sizeof(copy))
		return -EINVAL;
	strcpy(copy, text);
	dash = strchr(copy, '-');
	if (dash)
		*dash++ = '\0';
	if (parse_u32(copy, &first) || first > 65535)
		return -EINVAL;
	if (dash) {
		if (parse_u32(dash, &last) || last > 65535 || last < first)
			return -EINVAL;
	} else {
		last = first;
	}
	*from = first;
	*to = last;
	return 0;
}

static int set_family(struct rayfw_rule_wire *rule, uint8_t family)
{
	if (rule->family != RAYFW_FAMILY_ANY && rule->family != family)
		return -EAFNOSUPPORT;
	rule->family = family;
	return 0;
}

static int parse_cidr(const char *text, struct rayfw_rule_wire *rule, bool source)
{
	char copy[INET6_ADDRSTRLEN + 5];
	char *slash;
	uint8_t address[16] = {0};
	uint8_t family = strchr(text, ':') ? RAYFW_FAMILY_IPV6 : RAYFW_FAMILY_IPV4;
	uint32_t prefix = family == RAYFW_FAMILY_IPV6 ? 128 : 32;
	int af = family == RAYFW_FAMILY_IPV6 ? AF_INET6 : AF_INET;

	if (strlen(text) >= sizeof(copy))
		return -EINVAL;
	strcpy(copy, text);
	slash = strchr(copy, '/');
	if (slash) {
		*slash++ = '\0';
		if (parse_u32(slash, &prefix) || prefix > (family == RAYFW_FAMILY_IPV6 ? 128U : 32U))
			return -EINVAL;
	}
	if (inet_pton(af, copy, address) != 1 || set_family(rule, family))
		return -EINVAL;
	if (source) {
		memcpy(rule->src_addr, address, sizeof(address));
		rule->src_prefix = prefix;
		rule->flags |= RAYFW_RULE_F_SRC;
	} else {
		memcpy(rule->dst_addr, address, sizeof(address));
		rule->dst_prefix = prefix;
		rule->flags |= RAYFW_RULE_F_DST;
	}
	return 0;
}

static int parse_states(const char *text, uint32_t *states)
{
	char copy[128];
	char *token, *saveptr = NULL;
	uint32_t value = 0;

	if (strlen(text) >= sizeof(copy))
		return -EINVAL;
	strcpy(copy, text);
	for (token = strtok_r(copy, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		if (!strcasecmp(token, "new")) value |= RAYFW_CT_NEW;
		else if (!strcasecmp(token, "established")) value |= RAYFW_CT_ESTABLISHED;
		else if (!strcasecmp(token, "related")) value |= RAYFW_CT_RELATED;
		else if (!strcasecmp(token, "invalid")) value |= RAYFW_CT_INVALID;
		else if (!strcasecmp(token, "untracked")) value |= RAYFW_CT_UNTRACKED;
		else return -EINVAL;
	}
	if (!value)
		return -EINVAL;
	*states = value;
	return 0;
}

static int rule_attr_handler(struct nlmsghdr *nlh, void *context)
{
	struct rayfw_rule_wire *rule = context;
	struct genlmsghdr *genl = NLMSG_DATA(nlh);
	struct nlattr *table[RAYFW_A_MAX + 1];
	int remaining = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

	parse_attrs(table, RAYFW_A_MAX,
		    (struct nlattr *)((unsigned char *)genl + GENL_HDRLEN), remaining);
	if (!table[RAYFW_A_RULE] || attr_payload(table[RAYFW_A_RULE]) != sizeof(*rule))
		return -EPROTO;
	memcpy(rule, attr_data(table[RAYFW_A_RULE]), sizeof(*rule));
	return 0;
}

struct rule_list {
	struct rayfw_rule_wire *items;
	size_t count;
	size_t capacity;
};

static int collect_rule_handler(struct nlmsghdr *nlh, void *context)
{
	struct rule_list *list = context;
	struct rayfw_rule_wire rule;
	struct rayfw_rule_wire *new_items;
	int result = rule_attr_handler(nlh, &rule);

	if (result)
		return result;
	if (list->count == list->capacity) {
		size_t capacity = list->capacity ? list->capacity * 2 : 32;

		new_items = realloc(list->items, capacity * sizeof(*new_items));
		if (!new_items)
			return -ENOMEM;
		list->items = new_items;
		list->capacity = capacity;
	}
	list->items[list->count++] = rule;
	return 0;
}

static int get_rules(struct nl_client *client, struct rule_list *list)
{
	struct attr_buffer attrs = {0};

	memset(list, 0, sizeof(*list));
	return nl_request(client, RAYFW_CMD_LIST_RULES, &attrs, true, true,
			  collect_rule_handler, list);
}

struct status_data {
	bool enabled;
	uint32_t rule_count;
	uint8_t policies[RAYFW_CHAIN_MAX];
	char version[64];
};

static int status_handler(struct nlmsghdr *nlh, void *context)
{
	struct status_data *status = context;
	struct genlmsghdr *genl = NLMSG_DATA(nlh);
	struct nlattr *table[RAYFW_A_MAX + 1];
	int remaining = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

	parse_attrs(table, RAYFW_A_MAX,
		    (struct nlattr *)((unsigned char *)genl + GENL_HDRLEN), remaining);
	if (!table[RAYFW_A_ENABLED] || !table[RAYFW_A_VERSION] ||
	    !table[RAYFW_A_RULE_COUNT] || !table[RAYFW_A_POLICY_INPUT] ||
	    !table[RAYFW_A_POLICY_OUTPUT] || !table[RAYFW_A_POLICY_FORWARD])
		return -EPROTO;
	status->enabled = *(uint8_t *)attr_data(table[RAYFW_A_ENABLED]);
	memcpy(&status->rule_count, attr_data(table[RAYFW_A_RULE_COUNT]),
	       sizeof(status->rule_count));
	status->policies[0] = *(uint8_t *)attr_data(table[RAYFW_A_POLICY_INPUT]);
	status->policies[1] = *(uint8_t *)attr_data(table[RAYFW_A_POLICY_OUTPUT]);
	status->policies[2] = *(uint8_t *)attr_data(table[RAYFW_A_POLICY_FORWARD]);
	snprintf(status->version, sizeof(status->version), "%s",
		 (char *)attr_data(table[RAYFW_A_VERSION]));
	return 0;
}

static int get_status(struct nl_client *client, struct status_data *status)
{
	struct attr_buffer attrs = {0};

	memset(status, 0, sizeof(*status));
	return nl_request(client, RAYFW_CMD_GET_STATUS, &attrs, false, true,
			  status_handler, status);
}

static int command_status(struct nl_client *client)
{
	struct status_data status;
	int result = get_status(client, &status);

	if (result)
		return result;
	if (json_output) {
		printf("{\"enabled\":%s,\"version\":\"%s\",\"rules\":%u,"
		       "\"policy\":{\"input\":\"%s\",\"output\":\"%s\","
		       "\"forward\":\"%s\"}}\n",
		       status.enabled ? "true" : "false", status.version,
		       status.rule_count, policy_name(status.policies[0]),
		       policy_name(status.policies[1]), policy_name(status.policies[2]));
	} else {
		printf("防火墙状态: %s\n内核模块版本: %s\n规则数量: %u\n"
		       "默认策略: INPUT=%s  OUTPUT=%s  FORWARD=%s\n",
		       status.enabled ? "已启用" : "已停用（流量旁路）", status.version,
		       status.rule_count, policy_name(status.policies[0]),
		       policy_name(status.policies[1]), policy_name(status.policies[2]));
	}
	return 0;
}

static void format_address(const struct rayfw_rule_wire *rule, bool source,
			   char *output, size_t size)
{
	uint16_t flag = source ? RAYFW_RULE_F_SRC : RAYFW_RULE_F_DST;
	const uint8_t *address = source ? rule->src_addr : rule->dst_addr;
	uint8_t prefix = source ? rule->src_prefix : rule->dst_prefix;
	char text[INET6_ADDRSTRLEN];
	int af;

	if (!(rule->flags & flag)) {
		snprintf(output, size, "any");
		return;
	}
	af = rule->family == RAYFW_FAMILY_IPV6 ? AF_INET6 : AF_INET;
	if (!inet_ntop(af, address, text, sizeof(text)))
		snprintf(text, sizeof(text), "?");
	snprintf(output, size, "%s/%u", text, prefix);
}

static void format_ports(const struct rayfw_rule_wire *rule, bool source,
			 char *output, size_t size)
{
	uint16_t flag = source ? RAYFW_RULE_F_SPORT : RAYFW_RULE_F_DPORT;
	uint16_t from = source ? rule->src_port_from : rule->dst_port_from;
	uint16_t to = source ? rule->src_port_to : rule->dst_port_to;

	if (!(rule->flags & flag))
		snprintf(output, size, "any");
	else if (from == to)
		snprintf(output, size, "%u", from);
	else
		snprintf(output, size, "%u-%u", from, to);
}

static void format_states(uint32_t states, char *output, size_t size)
{
	struct { uint32_t bit; const char *name; } map[] = {
		{ RAYFW_CT_NEW, "new" }, { RAYFW_CT_ESTABLISHED, "established" },
		{ RAYFW_CT_RELATED, "related" }, { RAYFW_CT_INVALID, "invalid" },
		{ RAYFW_CT_UNTRACKED, "untracked" },
	};
	size_t used = 0;
	unsigned int i;

	output[0] = '\0';
	for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
		if (!(states & map[i].bit))
			continue;
		used += snprintf(output + used, used < size ? size - used : 0,
				 used ? ",%s" : "%s", map[i].name);
	}
}

static int command_list(struct nl_client *client)
{
	struct rule_list list;
	int result = get_rules(client, &list);
	size_t i;

	if (result)
		return result;
	if (json_output)
		printf("[");
	else if (!list.count)
		printf("当前没有规则。\n");
	else
		printf("%-6s %-8s %-5s %-7s %-7s %-22s %-22s %-11s %-11s %-9s %s\n",
		       "ID", "链", "族", "协议", "动作", "源地址", "目标地址",
		       "源端口", "目标端口", "优先级", "计数(包/字节)");
	for (i = 0; i < list.count; i++) {
		struct rayfw_rule_wire *r = &list.items[i];
		char src[INET6_ADDRSTRLEN + 8], dst[INET6_ADDRSTRLEN + 8];
		char sport[16], dport[16], states[96];

		format_address(r, true, src, sizeof(src));
		format_address(r, false, dst, sizeof(dst));
		format_ports(r, true, sport, sizeof(sport));
		format_ports(r, false, dport, sizeof(dport));
		format_states(r->ct_states, states, sizeof(states));
		if (json_output) {
			printf("%s{\"id\":%u,\"chain\":\"%s\",\"family\":\"%s\","
			       "\"protocol\":\"%s\",\"action\":\"%s\",\"source\":\"%s\","
			       "\"destination\":\"%s\",\"sport\":\"%s\",\"dport\":\"%s\","
			       "\"priority\":%d,\"states\":\"%s\",\"log\":%s,"
			       "\"packets\":%" PRIu64 ",\"bytes\":%" PRIu64 "}",
			       i ? "," : "", r->id, chain_name(r->chain), family_name(r->family),
			       protocol_name(r->protocol), action_name(r->action), src, dst,
			       sport, dport, r->priority, states,
			       (r->flags & RAYFW_RULE_F_LOG) ? "true" : "false",
			       (uint64_t)r->packets, (uint64_t)r->bytes);
		} else {
			printf("%-6u %-8s %-5s %-7s %-7s %-22s %-22s %-11s %-11s %-9d %" PRIu64 "/%" PRIu64,
			       r->id, chain_name(r->chain), family_name(r->family),
			       protocol_name(r->protocol), action_name(r->action), src, dst,
			       sport, dport, r->priority, (uint64_t)r->packets,
			       (uint64_t)r->bytes);
			if (r->flags & RAYFW_RULE_F_CT_STATE) printf(" state=%s", states);
			if (r->flags & RAYFW_RULE_F_IN_IF) printf(" in=%s", r->in_ifname);
			if (r->flags & RAYFW_RULE_F_OUT_IF) printf(" out=%s", r->out_ifname);
			if (r->flags & RAYFW_RULE_F_LOG) printf(" log");
			printf("\n");
		}
	}
	if (json_output)
		printf("]\n");
	free(list.items);
	return 0;
}

static int id_handler(struct nlmsghdr *nlh, void *context)
{
	uint32_t *id = context;
	struct genlmsghdr *genl = NLMSG_DATA(nlh);
	struct nlattr *table[RAYFW_A_MAX + 1];
	int remaining = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

	parse_attrs(table, RAYFW_A_MAX,
		    (struct nlattr *)((unsigned char *)genl + GENL_HDRLEN), remaining);
	if (!table[RAYFW_A_RULE_ID])
		return -EPROTO;
	memcpy(id, attr_data(table[RAYFW_A_RULE_ID]), sizeof(*id));
	return 0;
}

static int transaction_id_handler(struct nlmsghdr *nlh, void *context)
{
	uint32_t *id = context;
	struct genlmsghdr *genl = NLMSG_DATA(nlh);
	struct nlattr *table[RAYFW_A_MAX + 1];
	int remaining = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

	parse_attrs(table, RAYFW_A_MAX,
		    (struct nlattr *)((unsigned char *)genl + GENL_HDRLEN), remaining);
	if (!table[RAYFW_A_TX_ID])
		return -EPROTO;
	memcpy(id, attr_data(table[RAYFW_A_TX_ID]), sizeof(*id));
	return 0;
}

static int parse_add_rule(int argc, char **argv, struct rayfw_rule_wire *rule)
{
	bool have_chain = false, have_action = false;
	int i;

	memset(rule, 0, sizeof(*rule));
	rule->api_version = RAYFW_API_VERSION;
	rule->struct_size = sizeof(*rule);
	rule->priority = 1000;
	for (i = 0; i < argc; i++) {
		const char *option = argv[i];
		const char *value = NULL;

		if (!strcmp(option, "--log")) {
			rule->flags |= RAYFW_RULE_F_LOG;
			continue;
		}
		if (i + 1 >= argc)
			return -EINVAL;
		value = argv[++i];
		if (!strcmp(option, "--chain")) {
			if (parse_chain(value, &rule->chain, false)) return -EINVAL;
			have_chain = true;
		} else if (!strcmp(option, "--action")) {
			if (parse_policy(value, &rule->action)) return -EINVAL;
			have_action = true;
		} else if (!strcmp(option, "--family")) {
			uint8_t family;
			if (!strcasecmp(value, "any")) family = RAYFW_FAMILY_ANY;
			else if (!strcasecmp(value, "ipv4")) family = RAYFW_FAMILY_IPV4;
			else if (!strcasecmp(value, "ipv6")) family = RAYFW_FAMILY_IPV6;
			else return -EINVAL;
			if ((rule->flags & (RAYFW_RULE_F_SRC | RAYFW_RULE_F_DST)) &&
			    family == RAYFW_FAMILY_ANY) return -EINVAL;
			if (rule->family != RAYFW_FAMILY_ANY && family != RAYFW_FAMILY_ANY &&
			    rule->family != family) return -EINVAL;
			rule->family = family;
		} else if (!strcmp(option, "--proto")) {
			if (!strcasecmp(value, "any")) rule->protocol = RAYFW_PROTO_ANY;
			else if (!strcasecmp(value, "tcp")) rule->protocol = RAYFW_PROTO_TCP;
			else if (!strcasecmp(value, "udp")) rule->protocol = RAYFW_PROTO_UDP;
			else if (!strcasecmp(value, "icmp")) rule->protocol = RAYFW_PROTO_ICMP;
			else if (!strcasecmp(value, "icmpv6")) rule->protocol = RAYFW_PROTO_ICMPV6;
			else return -EINVAL;
		} else if (!strcmp(option, "--src")) {
			if (parse_cidr(value, rule, true)) return -EINVAL;
		} else if (!strcmp(option, "--dst")) {
			if (parse_cidr(value, rule, false)) return -EINVAL;
		} else if (!strcmp(option, "--sport")) {
			if (parse_port_range(value, &rule->src_port_from, &rule->src_port_to)) return -EINVAL;
			rule->flags |= RAYFW_RULE_F_SPORT;
		} else if (!strcmp(option, "--dport")) {
			if (parse_port_range(value, &rule->dst_port_from, &rule->dst_port_to)) return -EINVAL;
			rule->flags |= RAYFW_RULE_F_DPORT;
		} else if (!strcmp(option, "--in") || !strcmp(option, "--out")) {
			char *target = !strcmp(option, "--in") ? rule->in_ifname : rule->out_ifname;
			uint16_t flag = !strcmp(option, "--in") ? RAYFW_RULE_F_IN_IF : RAYFW_RULE_F_OUT_IF;
			if (!*value || strlen(value) >= RAYFW_IFNAME_LEN) return -EINVAL;
			strcpy(target, value);
			rule->flags |= flag;
		} else if (!strcmp(option, "--state")) {
			if (parse_states(value, &rule->ct_states)) return -EINVAL;
			rule->flags |= RAYFW_RULE_F_CT_STATE;
		} else if (!strcmp(option, "--priority")) {
			if (parse_priority(value, &rule->priority)) return -EINVAL;
		} else {
			return -EINVAL;
		}
	}
	if (!have_chain || !have_action)
		return -EINVAL;
	if ((rule->flags & (RAYFW_RULE_F_SPORT | RAYFW_RULE_F_DPORT)) &&
	    rule->protocol != RAYFW_PROTO_TCP && rule->protocol != RAYFW_PROTO_UDP)
		return -EPROTONOSUPPORT;
	return 0;
}

static int command_add(struct nl_client *client, int argc, char **argv, bool quiet)
{
	struct rayfw_rule_wire rule;
	struct attr_buffer attrs = {0};
	uint32_t id = 0;
	int result = parse_add_rule(argc, argv, &rule);

	if (result)
		return result;
	result = attr_add(&attrs, RAYFW_A_RULE, &rule, sizeof(rule));
	if (!result) result = attr_add_transaction(client, &attrs);
	if (!result)
		result = nl_request(client, RAYFW_CMD_ADD_RULE, &attrs, false, true,
				    id_handler, &id);
	if (!result && !quiet)
		printf(json_output ? "{\"id\":%u}\n" : "规则已添加，ID=%u\n", id);
	return result;
}

static int command_delete(struct nl_client *client, const char *text)
{
	struct attr_buffer attrs = {0};
	uint32_t id;
	int result = parse_u32(text, &id);

	if (!result) result = attr_add_u32(&attrs, RAYFW_A_RULE_ID, id);
	if (!result) result = attr_add_transaction(client, &attrs);
	if (!result) result = nl_request(client, RAYFW_CMD_DELETE_RULE, &attrs,
					 false, false, NULL, NULL);
	if (!result) printf("规则 %u 已删除。\n", id);
	return result;
}

static int command_flush(struct nl_client *client, const char *text, bool quiet)
{
	struct attr_buffer attrs = {0};
	uint8_t chain = RAYFW_CHAIN_ALL;
	int result = 0;

	if (text && parse_chain(text, &chain, true)) return -EINVAL;
	if (text) result = attr_add_u8(&attrs, RAYFW_A_CHAIN, chain);
	if (!result) result = attr_add_transaction(client, &attrs);
	if (!result) result = nl_request(client, RAYFW_CMD_FLUSH_RULES, &attrs,
					 false, false, NULL, NULL);
	if (!result && !quiet) printf("规则已清空。\n");
	return result;
}

static int command_policy(struct nl_client *client, const char *chain_text,
			  const char *policy_text, bool quiet)
{
	struct attr_buffer attrs = {0};
	uint8_t chain, policy;
	int result;

	if (parse_chain(chain_text, &chain, false) || parse_policy(policy_text, &policy))
		return -EINVAL;
	result = attr_add_u8(&attrs, RAYFW_A_CHAIN, chain);
	if (!result) result = attr_add_u8(&attrs, RAYFW_A_POLICY, policy);
	if (!result) result = attr_add_transaction(client, &attrs);
	if (!result) result = nl_request(client, RAYFW_CMD_SET_POLICY, &attrs,
					 false, false, NULL, NULL);
	if (!result && !quiet)
		printf("%s 默认策略已设为 %s。\n", chain_name(chain), policy_name(policy));
	return result;
}

static int command_enabled(struct nl_client *client, bool enabled, bool quiet)
{
	struct attr_buffer attrs = {0};
	int result = attr_add_u8(&attrs, RAYFW_A_ENABLED, enabled);

	if (!result) result = attr_add_transaction(client, &attrs);
	if (!result) result = nl_request(client, RAYFW_CMD_SET_ENABLED, &attrs,
					 false, false, NULL, NULL);
	if (!result && !quiet) printf("防火墙已%s。\n", enabled ? "启用" : "停用");
	return result;
}

static int command_reset_counters(struct nl_client *client)
{
	struct attr_buffer attrs = {0};
	int result = nl_request(client, RAYFW_CMD_RESET_COUNTERS, &attrs,
				false, false, NULL, NULL);

	if (!result) printf("所有规则计数器已清零。\n");
	return result;
}

static int command_transaction_begin(struct nl_client *client)
{
	struct attr_buffer attrs = {0};
	uint32_t id = 0;
	int result;

	if (client->transaction_id)
		return -EBUSY;
	result = nl_request(client, RAYFW_CMD_TX_BEGIN, &attrs, false, true,
			    transaction_id_handler, &id);
	if (!result)
		client->transaction_id = id;
	return result;
}

static int command_transaction_finish(struct nl_client *client, bool commit)
{
	struct attr_buffer attrs = {0};
	uint32_t id = client->transaction_id;
	int result;

	if (!id)
		return -EINVAL;
	result = attr_add_u32(&attrs, RAYFW_A_TX_ID, id);
	if (!result)
		result = nl_request(client, commit ? RAYFW_CMD_TX_COMMIT : RAYFW_CMD_TX_ABORT,
				    &attrs, false, false, NULL, NULL);
	if (!result)
		client->transaction_id = 0;
	return result;
}

static void write_rule(FILE *file, const struct rayfw_rule_wire *r)
{
	char src[INET6_ADDRSTRLEN + 8], dst[INET6_ADDRSTRLEN + 8];
	char sport[16], dport[16], states[96];

	format_address(r, true, src, sizeof(src));
	format_address(r, false, dst, sizeof(dst));
	format_ports(r, true, sport, sizeof(sport));
	format_ports(r, false, dport, sizeof(dport));
	format_states(r->ct_states, states, sizeof(states));
	fprintf(file, "add --chain %s --action %s --family %s --proto %s --priority %d",
		chain_name(r->chain), action_name(r->action), family_name(r->family),
		protocol_name(r->protocol), r->priority);
	if (r->flags & RAYFW_RULE_F_SRC) fprintf(file, " --src %s", src);
	if (r->flags & RAYFW_RULE_F_DST) fprintf(file, " --dst %s", dst);
	if (r->flags & RAYFW_RULE_F_SPORT) fprintf(file, " --sport %s", sport);
	if (r->flags & RAYFW_RULE_F_DPORT) fprintf(file, " --dport %s", dport);
	if (r->flags & RAYFW_RULE_F_IN_IF) fprintf(file, " --in %s", r->in_ifname);
	if (r->flags & RAYFW_RULE_F_OUT_IF) fprintf(file, " --out %s", r->out_ifname);
	if (r->flags & RAYFW_RULE_F_CT_STATE) fprintf(file, " --state %s", states);
	if (r->flags & RAYFW_RULE_F_LOG) fprintf(file, " --log");
	fputc('\n', file);
}

static int command_save(struct nl_client *client, const char *path)
{
	struct status_data status;
	struct rule_list list;
	char temporary[4096];
	FILE *file;
	int fd, result;
	size_t i;

	result = get_status(client, &status);
	if (result) return result;
	result = get_rules(client, &list);
	if (result) return result;
	if (snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path, (long)getpid()) >=
	    (int)sizeof(temporary)) {
		free(list.items);
		return -ENAMETOOLONG;
	}
	fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) { free(list.items); return -errno; }
	file = fdopen(fd, "w");
	if (!file) { result = -errno; close(fd); unlink(temporary); free(list.items); return result; }
	fprintf(file, "# RayFireWall configuration v1\n");
	fprintf(file, "policy input %s\n", policy_name(status.policies[0]));
	fprintf(file, "policy output %s\n", policy_name(status.policies[1]));
	fprintf(file, "policy forward %s\n", policy_name(status.policies[2]));
	for (i = 0; i < list.count; i++) write_rule(file, &list.items[i]);
	fprintf(file, "%s\n", status.enabled ? "enable" : "disable");
	free(list.items);
	if (fflush(file) || fsync(fd)) {
		result = -errno;
		fclose(file);
		unlink(temporary);
		return result;
	}
	if (fclose(file)) {
		result = -errno;
		unlink(temporary);
		return result;
	}
	if (rename(temporary, path)) { result = -errno; unlink(temporary); return result; }
	printf("配置已保存到 %s（权限 0600）。\n", path);
	return 0;
}

static int split_line(char *line, char **argv, int maximum)
{
	int argc = 0;
	char *saveptr = NULL;
	char *token;

	for (token = strtok_r(line, " \t\r\n", &saveptr); token;
	     token = strtok_r(NULL, " \t\r\n", &saveptr)) {
		if (*token == '#') break;
		if (argc == maximum) return -E2BIG;
		argv[argc++] = token;
	}
	return argc;
}

static int apply_config_line(struct nl_client *client, int argc, char **argv)
{
	if (!argc) return 0;
	if (!strcasecmp(argv[0], "add")) return command_add(client, argc - 1, argv + 1, true);
	if (!strcasecmp(argv[0], "policy") && argc == 3)
		return command_policy(client, argv[1], argv[2], true);
	if (!strcasecmp(argv[0], "enable") && argc == 1) return command_enabled(client, true, true);
	if (!strcasecmp(argv[0], "disable") && argc == 1) return command_enabled(client, false, true);
	return -EINVAL;
}

static int validate_config_line(int argc, char **argv)
{
	struct rayfw_rule_wire rule;
	uint8_t chain, policy;

	if (!argc) return 0;
	if (!strcasecmp(argv[0], "add")) return parse_add_rule(argc - 1, argv + 1, &rule);
	if (!strcasecmp(argv[0], "policy") && argc == 3)
		return parse_chain(argv[1], &chain, false) || parse_policy(argv[2], &policy) ?
		       -EINVAL : 0;
	if ((!strcasecmp(argv[0], "enable") || !strcasecmp(argv[0], "disable")) && argc == 1)
		return 0;
	return -EINVAL;
}

static int command_check(const char *path)
{
	FILE *file = fopen(path, "r");
	char *line = NULL;
	size_t capacity = 0;
	unsigned long line_number = 0;
	int result = 0;

	if (!file) return -errno;
	while (getline(&line, &capacity, file) >= 0) {
		char *argv[64];
		int argc;

		line_number++;
		argc = split_line(line, argv, 64);
		if (argc < 0) result = argc;
		else result = validate_config_line(argc, argv);
		if (result) {
			fprintf(stderr, "配置文件第 %lu 行无效。\n", line_number);
			break;
		}
	}
	if (!result && ferror(file)) result = -EIO;
	free(line);
	fclose(file);
	if (!result) printf("配置文件 %s 语法正确。\n", path);
	return result;
}

static int write_rollback_marker(const char *state, int flags)
{
	int fd;
	ssize_t written;
	size_t length = strlen(state);

	fd = open(ROLLBACK_MARKER, flags | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	if (flock(fd, LOCK_EX) < 0) {
		int result = -errno;

		close(fd);
		return result;
	}
	written = write(fd, state, length);
	if (written != (ssize_t)length || fsync(fd)) {
		int result = written != (ssize_t)length ? -EIO : -errno;

		flock(fd, LOCK_UN);
		close(fd);
		return result;
	}
	flock(fd, LOCK_UN);
	close(fd);
	return 0;
}

static int create_rollback_marker(const char *token)
{
	struct stat status;
	char state[96];
	int result;

	if (geteuid() != 0)
		return -EPERM;
	if (mkdir(ROLLBACK_DIR, 0700) && errno != EEXIST)
		return -errno;
	if (stat(ROLLBACK_DIR, &status))
		return -errno;
	if (!S_ISDIR(status.st_mode))
		return -ENOTDIR;
	if (snprintf(state, sizeof(state), "pending %s\n", token) >= (int)sizeof(state))
		return -ENAMETOOLONG;
	result = write_rollback_marker(state, O_WRONLY | O_CREAT | O_EXCL);
	return result == -EEXIST ? -EBUSY : result;
}

static void rollback_watchdog(unsigned int timeout, const char *token)
{
	struct nl_client client;
	char state[96] = {0};
	char armed_state[96], pending_state[96];
	unsigned int remaining = timeout;
	struct stat opened, current;
	int fd, armed_length, pending_length;
	ssize_t length;
	bool owns_marker = false;

	while (remaining)
		remaining = sleep(remaining);
	fd = open(ROLLBACK_MARKER, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		_exit(EXIT_SUCCESS);
	if (flock(fd, LOCK_EX) < 0) {
		close(fd);
		_exit(EXIT_FAILURE);
	}
	length = read(fd, state, sizeof(state) - 1);
	armed_length = snprintf(armed_state, sizeof(armed_state), "armed %s\n", token);
	pending_length = snprintf(pending_state, sizeof(pending_state), "pending %s\n", token);
	if (armed_length > 0 && armed_length < (int)sizeof(armed_state) &&
	    pending_length > 0 && pending_length < (int)sizeof(pending_state) &&
	    !fstat(fd, &opened) && !stat(ROLLBACK_MARKER, &current) &&
	    opened.st_dev == current.st_dev && opened.st_ino == current.st_ino &&
	    ((length == armed_length && !memcmp(state, armed_state, (size_t)length)) ||
	     (length == pending_length && !memcmp(state, pending_state, (size_t)length))))
		owns_marker = true;
	if (owns_marker && length == armed_length) {
		if (!nl_open_client(&client)) {
			command_enabled(&client, false, true);
			close(client.fd);
		}
	}
	if (owns_marker)
		unlink(ROLLBACK_MARKER);
	flock(fd, LOCK_UN);
	close(fd);
	_exit(EXIT_SUCCESS);
}

static int start_rollback_watchdog(unsigned int timeout, const char *token)
{
	int pipefd[2];
	pid_t pid;
	char ready;
	ssize_t received;

	if (pipe(pipefd))
		return -errno;
	pid = fork();
	if (pid < 0) {
		int result = -errno;

		close(pipefd[0]);
		close(pipefd[1]);
		return result;
	}
	if (pid == 0) {
		close(pipefd[0]);
		signal(SIGHUP, SIG_IGN);
		if (setsid() < 0) {
			(void)write(pipefd[1], "0", 1);
			close(pipefd[1]);
			_exit(EXIT_FAILURE);
		}
		(void)write(pipefd[1], "1", 1);
		close(pipefd[1]);
		rollback_watchdog(timeout, token);
	}
	close(pipefd[1]);
	received = read(pipefd[0], &ready, 1);
	close(pipefd[0]);
	return received == 1 && ready == '1' ? 0 : -EIO;
}

static int command_confirm(void)
{
	char state[96] = {0};
	int fd, result = 0;
	ssize_t length;

	if (geteuid() != 0)
		return -EPERM;
	fd = open(ROLLBACK_MARKER, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? -ENODATA : -errno;
	if (flock(fd, LOCK_EX) < 0) {
		result = -errno;
		goto out;
	}
	length = read(fd, state, sizeof(state) - 1);
	if (length < 7 || memcmp(state, "armed ", 6) || state[length - 1] != '\n') {
		result = -EAGAIN;
		goto unlock;
	}
	if (unlink(ROLLBACK_MARKER))
		result = -errno;
unlock:
	flock(fd, LOCK_UN);
out:
	close(fd);
	if (!result)
		printf("已确认当前配置，自动旁路保护已取消。\n");
	return result;
}

static int command_load(struct nl_client *client, const char *path)
{
	FILE *file = fopen(path, "r");
	char *line = NULL;
	size_t capacity = 0;
	unsigned long line_number = 0;
	bool desired_enabled = false;
	bool transaction_started = false;
	int result = 0;

	if (!file) return -errno;
	/* Validate the complete file before changing the active firewall. */
	while (getline(&line, &capacity, file) >= 0) {
		char *argv[64];
		int argc;

		line_number++;
		argc = split_line(line, argv, 64);
		if (argc < 0) result = argc;
		else result = validate_config_line(argc, argv);
		if (result) {
			fprintf(stderr, "配置文件第 %lu 行无效，现有规则未更改。\n", line_number);
			goto out;
		}
	}
	if (ferror(file)) {
		result = -EIO;
		goto out;
	}
	rewind(file);
	line_number = 0;
	result = command_transaction_begin(client);
	if (result)
		goto out;
	transaction_started = true;
	result = command_enabled(client, false, true);
	if (!result) result = command_policy(client, "input", "accept", true);
	if (!result) result = command_policy(client, "output", "accept", true);
	if (!result) result = command_policy(client, "forward", "accept", true);
	if (!result) result = command_flush(client, NULL, true);
	while (!result && getline(&line, &capacity, file) >= 0) {
		char *argv[64];
		int argc;

		line_number++;
		argc = split_line(line, argv, 64);
		if (argc < 0) {
			result = argc;
		} else if (argc == 1 && !strcasecmp(argv[0], "enable")) {
			desired_enabled = true;
		} else if (argc == 1 && !strcasecmp(argv[0], "disable")) {
			desired_enabled = false;
		} else {
			result = apply_config_line(client, argc, argv);
		}
		if (result)
			fprintf(stderr, "配置文件第 %lu 行无效。\n", line_number);
	}
	if (!result && ferror(file)) result = -EIO;
	if (!result) result = command_enabled(client, desired_enabled, true);
	if (!result) {
		result = command_transaction_finish(client, true);
		transaction_started = false;
	}
out:
	if (transaction_started) {
		int abort_result = command_transaction_finish(client, false);

		if (!result)
			result = abort_result;
	}
	free(line);
	fclose(file);
	if (!result) printf("配置已从 %s 恢复。\n", path);
	else fprintf(stderr, "恢复失败，活动防火墙未被修改，请修复配置后重试。\n");
	return result;
}

static int command_load_with_rollback(struct nl_client *client, const char *path,
					      unsigned int timeout)
{
	struct timespec now;
	char token[64], state[96];
	int result;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -errno;
	if (snprintf(token, sizeof(token), "%ld-%ld-%ld", (long)getpid(),
		     (long)now.tv_sec, (long)now.tv_nsec) >= (int)sizeof(token))
		return -ENAMETOOLONG;
	result = create_rollback_marker(token);
	if (result)
		return result;
	result = start_rollback_watchdog(timeout, token);
	if (result) {
		unlink(ROLLBACK_MARKER);
		return result;
	}
	result = command_load(client, path);
	if (result) {
		unlink(ROLLBACK_MARKER);
		return result;
	}
	if (snprintf(state, sizeof(state), "armed %s\n", token) >= (int)sizeof(state)) {
		unlink(ROLLBACK_MARKER);
		return -ENAMETOOLONG;
	}
	result = write_rollback_marker(state, O_WRONLY | O_TRUNC);
	if (result) {
		int disable_result = command_enabled(client, false, true);

		unlink(ROLLBACK_MARKER);
		return disable_result ? disable_result : result;
	}
	printf("配置将在 %u 秒后自动旁路；确认远程连接正常后执行: sudo rayfwctl confirm\n",
	       timeout);
	return 0;
}

static int command_load_args(struct nl_client *client, int argc, char **argv)
{
	const char *path = DEFAULT_CONFIG;
	unsigned int timeout = 0;
	bool have_path = false;
	int i;

	for (i = 0; i < argc; i++) {
		uint32_t parsed;

		if (!strcmp(argv[i], "--confirm-timeout")) {
			if (++i >= argc || timeout || parse_u32(argv[i], &parsed) ||
			    parsed < ROLLBACK_MIN_TIMEOUT || parsed > ROLLBACK_MAX_TIMEOUT)
				return -EINVAL;
			timeout = parsed;
		} else if (!have_path && argv[i][0] != '-') {
			path = argv[i];
			have_path = true;
		} else {
			return -EINVAL;
		}
	}
	return timeout ? command_load_with_rollback(client, path, timeout) :
		command_load(client, path);
}

static int command_logs(bool follow)
{
	if (follow)
		execlp("journalctl", "journalctl", "-k", "-f", "-g", "rayfw:", (char *)NULL);
	else
		execlp("journalctl", "journalctl", "-k", "-g", "rayfw:", "--no-pager", (char *)NULL);
	return -errno;
}

static bool command_is(const char *actual, const char *english, const char *chinese)
{
	return !strcasecmp(actual, english) || !strcmp(actual, chinese);
}

static int dispatch(struct nl_client *client, int argc, char **argv)
{
	const char *command = argv[0];

	if (command_is(command, "status", "状态") && argc == 1) return command_status(client);
	if (command_is(command, "list", "规则") && argc == 1) return command_list(client);
	if (command_is(command, "add", "添加") && argc >= 2) return command_add(client, argc - 1, argv + 1, false);
	if (command_is(command, "delete", "删除") && argc == 2) return command_delete(client, argv[1]);
	if (command_is(command, "flush", "清空") && argc <= 2) return command_flush(client, argc == 2 ? argv[1] : NULL, false);
	if (command_is(command, "policy", "策略") && argc == 3) return command_policy(client, argv[1], argv[2], false);
	if (command_is(command, "enable", "启用") && argc == 1) return command_enabled(client, true, false);
	if (command_is(command, "disable", "停用") && argc == 1) return command_enabled(client, false, false);
	if (command_is(command, "reset-counters", "计数清零") && argc == 1) return command_reset_counters(client);
	if (command_is(command, "save", "保存") && argc <= 2) return command_save(client, argc == 2 ? argv[1] : DEFAULT_CONFIG);
	if (command_is(command, "load", "加载")) return command_load_args(client, argc - 1, argv + 1);
	return -EINVAL;
}

static void print_error(int error)
{
	if (error == -ENODATA)
		fprintf(stderr, "没有待确认的配置加载。\n");
	else if (error == -ENOENT)
		fprintf(stderr, "RayFireWall 内核模块未加载，先运行: sudo modprobe rayfw\n");
	else if (error == -EPERM || error == -EACCES)
		fprintf(stderr, "权限不足，修改防火墙需要 root 或 CAP_NET_ADMIN。\n");
	else if (error == -EBUSY)
		fprintf(stderr, "已有一项待确认的配置加载，请先确认或等待其自动旁路。\n");
	else if (error == -EAGAIN)
		fprintf(stderr, "没有可确认的已加载配置。\n");
	else if (error == -EINVAL || error == -EPROTONOSUPPORT || error == -EAFNOSUPPORT)
		fprintf(stderr, "参数无效或选项组合不受支持，可运行 rayfwctl help 查看用法。\n");
	else
		fprintf(stderr, "操作失败: %s (%d)\n", strerror(-error), -error);
}

int main(int argc, char **argv)
{
	struct nl_client client;
	int result;

	if (argc > 1 && !strcmp(argv[1], "--json")) {
		json_output = true;
		argv++;
		argc--;
	}
	if (argc < 2 || command_is(argv[1], "help", "帮助") || !strcmp(argv[1], "--help")) {
		print_help(argc < 2 ? stderr : stdout);
		return argc < 2 ? EXIT_FAILURE : EXIT_SUCCESS;
	}
	if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "version")) {
		printf("rayfwctl %s\n", RAYFWCTL_VERSION);
		return EXIT_SUCCESS;
	}
	if (command_is(argv[1], "logs", "日志")) {
		if (argc > 3 || (argc == 3 && strcmp(argv[2], "-f"))) result = -EINVAL;
		else result = command_logs(argc == 3);
		if (result) print_error(result);
		return result ? EXIT_FAILURE : EXIT_SUCCESS;
	}
	if (command_is(argv[1], "check", "检查")) {
		if (argc > 3) result = -EINVAL;
		else result = command_check(argc == 3 ? argv[2] : DEFAULT_CONFIG);
		if (result) print_error(result);
		return result ? EXIT_FAILURE : EXIT_SUCCESS;
	}
	if (command_is(argv[1], "confirm", "确认")) {
		result = argc == 2 ? command_confirm() : -EINVAL;
		if (result) print_error(result);
		return result ? EXIT_FAILURE : EXIT_SUCCESS;
	}
	result = nl_open_client(&client);
	if (result) {
		print_error(result);
		return EXIT_FAILURE;
	}
	result = dispatch(&client, argc - 1, argv + 1);
	close(client.fd);
	if (result) print_error(result);
	return result ? EXIT_FAILURE : EXIT_SUCCESS;
}
