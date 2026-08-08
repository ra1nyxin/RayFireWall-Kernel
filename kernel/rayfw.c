// SPDX-License-Identifier: GPL-2.0
#include <linux/atomic.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netlink.h>
#include <linux/ratelimit.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/netfilter/nf_conntrack.h>

#include <uapi/rayfw.h>

#define RAYFW_VERSION "0.1.0"
#define RAYFW_DEFAULT_MAX_RULES 1024
#define RAYFW_DEFAULT_TX_TIMEOUT_MS 30000

struct rayfw_rule {
	struct list_head node;
	struct rayfw_rule_wire spec;
	atomic64_t packets;
	atomic64_t bytes;
	struct ratelimit_state log_limit;
};

struct rayfw_net;

struct rayfw_hook_context {
	struct rayfw_net *rnet;
	u8 chain;
};

struct rayfw_ruleset {
	struct rcu_head rcu;
	struct list_head rules[RAYFW_CHAIN_MAX];
	u8 policy[RAYFW_CHAIN_MAX];
	bool enabled;
	u32 rule_count;
};

struct rayfw_transaction {
	u32 id;
	u32 portid;
	struct rayfw_net *rnet;
	struct rayfw_ruleset *staged;
	struct delayed_work timeout_work;
};

struct rayfw_net {
	struct mutex lock;
	struct rayfw_ruleset __rcu *active;
	struct rayfw_transaction *transaction;
	u32 next_id;
	u32 next_transaction_id;
	struct rayfw_hook_context contexts[6];
	struct nf_hook_ops hooks[6];
};

static unsigned int rayfw_net_id;
static struct genl_family rayfw_genl_family;
static unsigned int max_rules_per_net = RAYFW_DEFAULT_MAX_RULES;
module_param(max_rules_per_net, uint, 0644);
MODULE_PARM_DESC(max_rules_per_net, "Maximum rules allowed in one network namespace");
static unsigned int transaction_timeout_ms = RAYFW_DEFAULT_TX_TIMEOUT_MS;
module_param(transaction_timeout_ms, uint, 0644);
MODULE_PARM_DESC(transaction_timeout_ms, "Transaction auto-abort timeout in milliseconds");

static const struct nla_policy rayfw_nla_policy[RAYFW_A_MAX + 1] = {
	[RAYFW_A_RULE] = { .type = NLA_BINARY, .len = sizeof(struct rayfw_rule_wire) },
	[RAYFW_A_RULE_ID] = { .type = NLA_U32 },
	[RAYFW_A_CHAIN] = { .type = NLA_U8 },
	[RAYFW_A_POLICY] = { .type = NLA_U8 },
	[RAYFW_A_ENABLED] = { .type = NLA_U8 },
	[RAYFW_A_TX_ID] = { .type = NLA_U32 },
};

static bool rayfw_prefix_match(const u8 *packet, const u8 *rule, u8 bits)
{
	u8 full = bits / 8;
	u8 remaining = bits % 8;

	if (full && memcmp(packet, rule, full))
		return false;
	if (remaining) {
		u8 mask = (u8)(0xffU << (8 - remaining));

		if ((packet[full] & mask) != (rule[full] & mask))
			return false;
	}
	return true;
}

static u32 rayfw_ct_state(const struct sk_buff *skb)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

	if (ctinfo == IP_CT_UNTRACKED)
		return RAYFW_CT_UNTRACKED;
	if (!ct)
		return RAYFW_CT_INVALID;
	if (ctinfo == IP_CT_ESTABLISHED || ctinfo == IP_CT_ESTABLISHED_REPLY)
		return RAYFW_CT_ESTABLISHED;
	if (ctinfo == IP_CT_RELATED || ctinfo == IP_CT_RELATED_REPLY)
		return RAYFW_CT_RELATED;
	if (ctinfo == IP_CT_NEW)
		return RAYFW_CT_NEW;
	return RAYFW_CT_INVALID;
}

struct rayfw_packet {
	u8 family;
	u8 protocol;
	u8 src[16];
	u8 dst[16];
	u16 sport;
	u16 dport;
	bool has_ports;
};

static bool rayfw_parse_ipv4(const struct sk_buff *skb, struct rayfw_packet *pkt)
{
	struct iphdr iph_buf;
	const struct iphdr *iph;
	unsigned int offset;

	iph = skb_header_pointer(skb, 0, sizeof(iph_buf), &iph_buf);
	if (!iph || iph->version != 4 || iph->ihl < 5)
		return false;
	pkt->family = RAYFW_FAMILY_IPV4;
	pkt->protocol = iph->protocol;
	memcpy(pkt->src, &iph->saddr, 4);
	memcpy(pkt->dst, &iph->daddr, 4);
	offset = iph->ihl * 4;
	pkt->has_ports = false;
	/* The first fragment still contains the transport header. */
	if (ntohs(iph->frag_off) & IP_OFFSET)
		return true;

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr tcp_buf;
		const struct tcphdr *tcp;

		tcp = skb_header_pointer(skb, offset, sizeof(tcp_buf), &tcp_buf);
		if (!tcp)
			return true;
		pkt->sport = ntohs(tcp->source);
		pkt->dport = ntohs(tcp->dest);
		pkt->has_ports = true;
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr udp_buf;
		const struct udphdr *udp;

		udp = skb_header_pointer(skb, offset, sizeof(udp_buf), &udp_buf);
		if (!udp)
			return true;
		pkt->sport = ntohs(udp->source);
		pkt->dport = ntohs(udp->dest);
		pkt->has_ports = true;
	}
	return true;
}

static bool rayfw_parse_ipv6(const struct sk_buff *skb, struct rayfw_packet *pkt)
{
	struct ipv6hdr ip6_buf;
	const struct ipv6hdr *ip6h;
	unsigned int offset = sizeof(struct ipv6hdr);
	u8 nexthdr;
	__be16 frag_off = 0;
	int found;

	ip6h = skb_header_pointer(skb, 0, sizeof(ip6_buf), &ip6_buf);
	if (!ip6h || ip6h->version != 6)
		return false;
	pkt->family = RAYFW_FAMILY_IPV6;
	memcpy(pkt->src, &ip6h->saddr, 16);
	memcpy(pkt->dst, &ip6h->daddr, 16);
	nexthdr = ip6h->nexthdr;
	found = ipv6_skip_exthdr(skb, offset, &nexthdr, &frag_off);
	if (found >= 0)
		offset = found;
	pkt->protocol = nexthdr;
	pkt->has_ports = false;
	/* IP6_MF alone still denotes the first fragment with an L4 header. */
	if (found < 0 || (frag_off & htons(IP6_OFFSET)))
		return true;

	if (nexthdr == IPPROTO_TCP) {
		struct tcphdr tcp_buf;
		const struct tcphdr *tcp;

		tcp = skb_header_pointer(skb, offset, sizeof(tcp_buf), &tcp_buf);
		if (!tcp)
			return true;
		pkt->sport = ntohs(tcp->source);
		pkt->dport = ntohs(tcp->dest);
		pkt->has_ports = true;
	} else if (nexthdr == IPPROTO_UDP) {
		struct udphdr udp_buf;
		const struct udphdr *udp;

		udp = skb_header_pointer(skb, offset, sizeof(udp_buf), &udp_buf);
		if (!udp)
			return true;
		pkt->sport = ntohs(udp->source);
		pkt->dport = ntohs(udp->dest);
		pkt->has_ports = true;
	}
	return true;
}

static bool rayfw_rule_matches(const struct rayfw_rule_wire *r,
			       const struct rayfw_packet *pkt,
			       const struct nf_hook_state *state,
			       const struct sk_buff *skb)
{
	if (r->family != RAYFW_FAMILY_ANY && r->family != pkt->family)
		return false;
	if (r->protocol != RAYFW_PROTO_ANY && r->protocol != pkt->protocol)
		return false;
	if ((r->flags & RAYFW_RULE_F_SRC) &&
	    !rayfw_prefix_match(pkt->src, r->src_addr, r->src_prefix))
		return false;
	if ((r->flags & RAYFW_RULE_F_DST) &&
	    !rayfw_prefix_match(pkt->dst, r->dst_addr, r->dst_prefix))
		return false;
	if (r->flags & (RAYFW_RULE_F_SPORT | RAYFW_RULE_F_DPORT)) {
		if (!pkt->has_ports)
			return false;
		if ((r->flags & RAYFW_RULE_F_SPORT) &&
		    (pkt->sport < r->src_port_from || pkt->sport > r->src_port_to))
			return false;
		if ((r->flags & RAYFW_RULE_F_DPORT) &&
		    (pkt->dport < r->dst_port_from || pkt->dport > r->dst_port_to))
			return false;
	}
	if ((r->flags & RAYFW_RULE_F_IN_IF) &&
	    (!state->in || strncmp(state->in->name, r->in_ifname, RAYFW_IFNAME_LEN)))
		return false;
	if ((r->flags & RAYFW_RULE_F_OUT_IF) &&
	    (!state->out || strncmp(state->out->name, r->out_ifname, RAYFW_IFNAME_LEN)))
		return false;
	if ((r->flags & RAYFW_RULE_F_CT_STATE) &&
	    !(r->ct_states & rayfw_ct_state(skb)))
		return false;
	return true;
}

static void rayfw_log_match(struct rayfw_rule *rule,
			    const struct rayfw_packet *pkt,
			    const struct nf_hook_state *state, u8 chain,
			    unsigned int length)
{
	const char *in = state->in ? state->in->name : "-";
	const char *out = state->out ? state->out->name : "-";
	u16 sport = pkt->has_ports ? pkt->sport : 0;
	u16 dport = pkt->has_ports ? pkt->dport : 0;

	if (!__ratelimit(&rule->log_limit))
		return;
	if (pkt->family == RAYFW_FAMILY_IPV4)
		pr_info("rayfw: ns=%u rule=%u chain=%u action=%u src=%pI4:%u dst=%pI4:%u proto=%u in=%s out=%s len=%u\n",
			state->net->ns.inum, rule->spec.id, chain, rule->spec.action,
			pkt->src, sport, pkt->dst, dport, pkt->protocol, in, out, length);
	else
		pr_info("rayfw: ns=%u rule=%u chain=%u action=%u src=[%pI6c]:%u dst=[%pI6c]:%u proto=%u in=%s out=%s len=%u\n",
			state->net->ns.inum, rule->spec.id, chain, rule->spec.action,
			pkt->src, sport, pkt->dst, dport, pkt->protocol, in, out, length);
}

static unsigned int rayfw_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct rayfw_hook_context *ctx = priv;
	struct rayfw_ruleset *ruleset;
	struct rayfw_rule *rule;
	struct rayfw_packet pkt = {0};
	u8 verdict;

	rcu_read_lock();
	ruleset = rcu_dereference(ctx->rnet->active);
	if (!ruleset || !READ_ONCE(ruleset->enabled)) {
		rcu_read_unlock();
		return NF_ACCEPT;
	}
	if (state->pf == NFPROTO_IPV4) {
		if (!rayfw_parse_ipv4(skb, &pkt)) {
			rcu_read_unlock();
			return NF_DROP;
		}
	} else if (state->pf == NFPROTO_IPV6) {
		if (!rayfw_parse_ipv6(skb, &pkt)) {
			rcu_read_unlock();
			return NF_DROP;
		}
	} else {
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	list_for_each_entry_rcu(rule, &ruleset->rules[ctx->chain], node) {
		if (!rayfw_rule_matches(&rule->spec, &pkt, state, skb))
			continue;
		atomic64_inc(&rule->packets);
		atomic64_add(skb->len, &rule->bytes);
		if (rule->spec.flags & RAYFW_RULE_F_LOG)
			rayfw_log_match(rule, &pkt, state, ctx->chain, skb->len);
		verdict = rule->spec.action == RAYFW_ACTION_DROP ? NF_DROP : NF_ACCEPT;
		rcu_read_unlock();
		return verdict;
	}
	verdict = READ_ONCE(ruleset->policy[ctx->chain]);
	rcu_read_unlock();
	return verdict == RAYFW_POLICY_DROP ? NF_DROP : NF_ACCEPT;
}

static int rayfw_validate_rule(struct rayfw_rule_wire *r)
{
	u16 known_flags = RAYFW_RULE_F_LOG | RAYFW_RULE_F_SRC | RAYFW_RULE_F_DST |
		RAYFW_RULE_F_SPORT | RAYFW_RULE_F_DPORT | RAYFW_RULE_F_IN_IF |
		RAYFW_RULE_F_OUT_IF | RAYFW_RULE_F_CT_STATE;
	u32 known_states = RAYFW_CT_NEW | RAYFW_CT_ESTABLISHED | RAYFW_CT_RELATED |
		RAYFW_CT_INVALID | RAYFW_CT_UNTRACKED;

	if (r->api_version != RAYFW_API_VERSION ||
	    r->struct_size != sizeof(*r) || r->chain >= RAYFW_CHAIN_MAX)
		return -EINVAL;
	if (r->family != RAYFW_FAMILY_ANY && r->family != RAYFW_FAMILY_IPV4 &&
	    r->family != RAYFW_FAMILY_IPV6)
		return -EAFNOSUPPORT;
	if (r->protocol != RAYFW_PROTO_ANY && r->protocol != RAYFW_PROTO_TCP &&
	    r->protocol != RAYFW_PROTO_UDP && r->protocol != RAYFW_PROTO_ICMP &&
	    r->protocol != RAYFW_PROTO_ICMPV6)
		return -EPROTONOSUPPORT;
	if (r->action > RAYFW_ACTION_DROP || (r->flags & ~known_flags))
		return -EINVAL;
	if ((r->family == RAYFW_FAMILY_IPV4 && r->protocol == RAYFW_PROTO_ICMPV6) ||
	    (r->family == RAYFW_FAMILY_IPV6 && r->protocol == RAYFW_PROTO_ICMP))
		return -EPROTONOSUPPORT;
	if ((r->flags & RAYFW_RULE_F_SRC) &&
	    r->src_prefix > (r->family == RAYFW_FAMILY_IPV4 ? 32 : 128))
		return -EINVAL;
	if ((r->flags & RAYFW_RULE_F_DST) &&
	    r->dst_prefix > (r->family == RAYFW_FAMILY_IPV4 ? 32 : 128))
		return -EINVAL;
	if ((r->flags & (RAYFW_RULE_F_SRC | RAYFW_RULE_F_DST)) &&
	    r->family == RAYFW_FAMILY_ANY)
		return -EINVAL;
	if ((r->flags & RAYFW_RULE_F_SPORT) && r->src_port_from > r->src_port_to)
		return -EINVAL;
	if ((r->flags & RAYFW_RULE_F_DPORT) && r->dst_port_from > r->dst_port_to)
		return -EINVAL;
	if ((r->flags & (RAYFW_RULE_F_SPORT | RAYFW_RULE_F_DPORT)) &&
	    r->protocol != RAYFW_PROTO_TCP && r->protocol != RAYFW_PROTO_UDP)
		return -EINVAL;
	if ((r->flags & RAYFW_RULE_F_CT_STATE) &&
	    (!r->ct_states || (r->ct_states & ~known_states)))
		return -EINVAL;
	r->in_ifname[RAYFW_IFNAME_LEN - 1] = '\0';
	r->out_ifname[RAYFW_IFNAME_LEN - 1] = '\0';
	r->packets = 0;
	r->bytes = 0;
	return 0;
}

static void rayfw_ruleset_free(struct rayfw_ruleset *ruleset)
{
	struct rayfw_rule *rule, *tmp;
	int chain;

	if (!ruleset)
		return;
	for (chain = 0; chain < RAYFW_CHAIN_MAX; chain++) {
		list_for_each_entry_safe(rule, tmp, &ruleset->rules[chain], node) {
			list_del(&rule->node);
			kfree(rule);
		}
	}
	kfree(ruleset);
}

static void rayfw_ruleset_free_rcu(struct rcu_head *rcu)
{
	struct rayfw_ruleset *ruleset = container_of(rcu, struct rayfw_ruleset, rcu);

	rayfw_ruleset_free(ruleset);
}

static struct rayfw_ruleset *rayfw_ruleset_alloc(void)
{
	struct rayfw_ruleset *ruleset;
	int chain;

	ruleset = kzalloc(sizeof(*ruleset), GFP_KERNEL);
	if (!ruleset)
		return NULL;
	for (chain = 0; chain < RAYFW_CHAIN_MAX; chain++) {
		INIT_LIST_HEAD(&ruleset->rules[chain]);
		ruleset->policy[chain] = RAYFW_POLICY_ACCEPT;
	}
	ruleset->enabled = true;
	return ruleset;
}

static struct rayfw_rule *rayfw_rule_alloc(const struct rayfw_rule_wire *spec,
					    u64 packets, u64 bytes)
{
	struct rayfw_rule *rule = kzalloc(sizeof(*rule), GFP_KERNEL);

	if (!rule)
		return NULL;
	INIT_LIST_HEAD(&rule->node);
	rule->spec = *spec;
	atomic64_set(&rule->packets, packets);
	atomic64_set(&rule->bytes, bytes);
	ratelimit_state_init(&rule->log_limit, HZ, 10);
	return rule;
}

static void rayfw_insert_rule(struct rayfw_ruleset *ruleset, struct rayfw_rule *rule)
{
	struct rayfw_rule *pos;

	list_for_each_entry(pos, &ruleset->rules[rule->spec.chain], node) {
		if (rule->spec.priority < pos->spec.priority) {
			list_add_tail(&rule->node, &pos->node);
			return;
		}
	}
	list_add_tail(&rule->node, &ruleset->rules[rule->spec.chain]);
}

static struct rayfw_ruleset *rayfw_ruleset_clone(const struct rayfw_ruleset *source)
{
	struct rayfw_ruleset *clone;
	struct rayfw_rule *rule;
	int chain;

	clone = rayfw_ruleset_alloc();
	if (!clone)
		return NULL;
	clone->enabled = source->enabled;
	clone->rule_count = source->rule_count;
	memcpy(clone->policy, source->policy, sizeof(clone->policy));
	for (chain = 0; chain < RAYFW_CHAIN_MAX; chain++) {
		list_for_each_entry(rule, &source->rules[chain], node) {
			struct rayfw_rule *copy = rayfw_rule_alloc(&rule->spec,
				atomic64_read(&rule->packets), atomic64_read(&rule->bytes));

			if (!copy) {
				rayfw_ruleset_free(clone);
				return NULL;
			}
			list_add_tail(&copy->node, &clone->rules[chain]);
		}
	}
	return clone;
}

static void rayfw_publish_ruleset(struct rayfw_net *rnet,
				  struct rayfw_ruleset *replacement)
{
	struct rayfw_ruleset *old;

	old = rcu_dereference_protected(rnet->active,
			lockdep_is_held(&rnet->lock));
	rcu_assign_pointer(rnet->active, replacement);
	call_rcu(&old->rcu, rayfw_ruleset_free_rcu);
}

static int rayfw_mutable_ruleset(struct rayfw_net *rnet, struct genl_info *info,
				 struct rayfw_ruleset **ruleset, bool *publish)
{
	if (info->attrs[RAYFW_A_TX_ID]) {
		u32 id = nla_get_u32(info->attrs[RAYFW_A_TX_ID]);

		if (!rnet->transaction || rnet->transaction->id != id ||
		    rnet->transaction->portid != info->snd_portid)
			return -EPERM;
		*ruleset = rnet->transaction->staged;
		*publish = false;
		return 0;
	}
	if (rnet->transaction)
		return -EBUSY;
	*ruleset = rayfw_ruleset_clone(rcu_dereference_protected(rnet->active,
		lockdep_is_held(&rnet->lock)));
	if (!*ruleset)
		return -ENOMEM;
	*publish = true;
	return 0;
}

static void rayfw_finish_change(struct rayfw_net *rnet,
				struct rayfw_ruleset *ruleset, bool publish)
{
	if (publish)
		rayfw_publish_ruleset(rnet, ruleset);
}

static int rayfw_add_rule(struct sk_buff *skb, struct genl_info *info)
{
	struct rayfw_net *rnet = net_generic(genl_info_net(info), rayfw_net_id);
	struct rayfw_rule_wire spec;
	struct rayfw_ruleset *ruleset;
	struct rayfw_rule *rule;
	struct sk_buff *reply;
	void *hdr;
	struct nlattr *reply_attr;
	u32 *reply_id;
	bool publish;
	int err;

	if (!info->attrs[RAYFW_A_RULE])
		return -EINVAL;
	if (nla_len(info->attrs[RAYFW_A_RULE]) != sizeof(spec))
		return -EMSGSIZE;
	memcpy(&spec, nla_data(info->attrs[RAYFW_A_RULE]), sizeof(spec));
	err = rayfw_validate_rule(&spec);
	if (err)
		return err;
	reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;
	hdr = genlmsg_put_reply(reply, info, &rayfw_genl_family, 0,
				RAYFW_CMD_ADD_RULE);
	if (!hdr || !(reply_attr = nla_reserve(reply, RAYFW_A_RULE_ID, sizeof(*reply_id)))) {
		nlmsg_free(reply);
		return -EMSGSIZE;
	}
	reply_id = nla_data(reply_attr);

	mutex_lock(&rnet->lock);
	err = rayfw_mutable_ruleset(rnet, info, &ruleset, &publish);
	if (err)
		goto unlock;
	if (ruleset->rule_count >= max_rules_per_net) {
		err = -ENOSPC;
		goto free_ruleset;
	}
	if (!++rnet->next_id)
		++rnet->next_id;
	spec.id = rnet->next_id;
	rule = rayfw_rule_alloc(&spec, 0, 0);
	if (!rule) {
		err = -ENOMEM;
		goto free_ruleset;
	}
	rayfw_insert_rule(ruleset, rule);
	ruleset->rule_count++;
	rayfw_finish_change(rnet, ruleset, publish);
	mutex_unlock(&rnet->lock);
	*reply_id = spec.id;
	genlmsg_end(reply, hdr);
	return genlmsg_reply(reply, info);

free_ruleset:
	if (publish)
		rayfw_ruleset_free(ruleset);
unlock:
	mutex_unlock(&rnet->lock);
	nlmsg_free(reply);
	return err;
}

static int rayfw_delete_rule(struct sk_buff *skb, struct genl_info *info)
{
	struct rayfw_net *rnet = net_generic(genl_info_net(info), rayfw_net_id);
	struct rayfw_ruleset *ruleset;
	struct rayfw_rule *rule;
	bool publish;
	u32 id;
	int chain, err;

	if (!info->attrs[RAYFW_A_RULE_ID])
		return -EINVAL;
	id = nla_get_u32(info->attrs[RAYFW_A_RULE_ID]);
	mutex_lock(&rnet->lock);
	err = rayfw_mutable_ruleset(rnet, info, &ruleset, &publish);
	if (err)
		goto unlock;
	for (chain = 0; chain < RAYFW_CHAIN_MAX; chain++) {
		list_for_each_entry(rule, &ruleset->rules[chain], node) {
			if (rule->spec.id != id)
				continue;
			list_del(&rule->node);
			kfree(rule);
			ruleset->rule_count--;
			rayfw_finish_change(rnet, ruleset, publish);
			mutex_unlock(&rnet->lock);
			return 0;
		}
	}
	err = -ENOENT;
	if (publish)
		rayfw_ruleset_free(ruleset);
unlock:
	mutex_unlock(&rnet->lock);
	return err;
}

static int rayfw_flush_rules(struct sk_buff *skb, struct genl_info *info)
{
	struct rayfw_net *rnet = net_generic(genl_info_net(info), rayfw_net_id);
	struct rayfw_ruleset *ruleset;
	struct rayfw_rule *rule, *tmp;
	u8 requested = RAYFW_CHAIN_ALL;
	bool publish;
	int chain, err;

	if (info->attrs[RAYFW_A_CHAIN])
		requested = nla_get_u8(info->attrs[RAYFW_A_CHAIN]);
	if (requested != RAYFW_CHAIN_ALL && requested >= RAYFW_CHAIN_MAX)
		return -EINVAL;
	mutex_lock(&rnet->lock);
	err = rayfw_mutable_ruleset(rnet, info, &ruleset, &publish);
	if (err)
		goto unlock;
	for (chain = 0; chain < RAYFW_CHAIN_MAX; chain++) {
		if (requested != RAYFW_CHAIN_ALL && requested != chain)
			continue;
		list_for_each_entry_safe(rule, tmp, &ruleset->rules[chain], node) {
			list_del(&rule->node);
			kfree(rule);
			ruleset->rule_count--;
		}
	}
	rayfw_finish_change(rnet, ruleset, publish);
	mutex_unlock(&rnet->lock);
	return 0;
unlock:
	mutex_unlock(&rnet->lock);
	return err;
}

static int rayfw_set_policy(struct sk_buff *skb, struct genl_info *info)
{
	struct rayfw_net *rnet = net_generic(genl_info_net(info), rayfw_net_id);
	struct rayfw_ruleset *ruleset;
	u8 chain, policy;
	bool publish;
	int err;

	if (!info->attrs[RAYFW_A_CHAIN] || !info->attrs[RAYFW_A_POLICY])
		return -EINVAL;
	chain = nla_get_u8(info->attrs[RAYFW_A_CHAIN]);
	policy = nla_get_u8(info->attrs[RAYFW_A_POLICY]);
	if (chain >= RAYFW_CHAIN_MAX || policy > RAYFW_POLICY_DROP)
		return -EINVAL;
	mutex_lock(&rnet->lock);
	err = rayfw_mutable_ruleset(rnet, info, &ruleset, &publish);
	if (!err) {
		ruleset->policy[chain] = policy;
		rayfw_finish_change(rnet, ruleset, publish);
	}
	mutex_unlock(&rnet->lock);
	return err;
}

static int rayfw_set_enabled(struct sk_buff *skb, struct genl_info *info)
{
	struct rayfw_net *rnet = net_generic(genl_info_net(info), rayfw_net_id);
	struct rayfw_ruleset *ruleset;
	bool publish;
	int err;

	if (!info->attrs[RAYFW_A_ENABLED])
		return -EINVAL;
	mutex_lock(&rnet->lock);
	err = rayfw_mutable_ruleset(rnet, info, &ruleset, &publish);
	if (!err) {
		ruleset->enabled = !!nla_get_u8(info->attrs[RAYFW_A_ENABLED]);
		rayfw_finish_change(rnet, ruleset, publish);
	}
	mutex_unlock(&rnet->lock);
	return err;
}

static int rayfw_get_status(struct sk_buff *skb, struct genl_info *info)
{
	struct rayfw_net *rnet = net_generic(genl_info_net(info), rayfw_net_id);
	struct rayfw_ruleset *ruleset;
	struct sk_buff *reply;
	void *hdr;
	u8 enabled, policy[RAYFW_CHAIN_MAX];
	u32 rule_count;

	rcu_read_lock();
	ruleset = rcu_dereference(rnet->active);
	enabled = ruleset->enabled;
	rule_count = ruleset->rule_count;
	memcpy(policy, ruleset->policy, sizeof(policy));
	rcu_read_unlock();
	reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;
	hdr = genlmsg_put_reply(reply, info, &rayfw_genl_family, 0,
				RAYFW_CMD_GET_STATUS);
	if (!hdr)
		goto nla_fail;
	if (nla_put_u8(reply, RAYFW_A_ENABLED, enabled) ||
	    nla_put_string(reply, RAYFW_A_VERSION, RAYFW_VERSION) ||
	    nla_put_u32(reply, RAYFW_A_RULE_COUNT, rule_count) ||
	    nla_put_u8(reply, RAYFW_A_POLICY_INPUT, policy[RAYFW_CHAIN_INPUT]) ||
	    nla_put_u8(reply, RAYFW_A_POLICY_OUTPUT, policy[RAYFW_CHAIN_OUTPUT]) ||
	    nla_put_u8(reply, RAYFW_A_POLICY_FORWARD, policy[RAYFW_CHAIN_FORWARD]))
		goto nla_fail;
	genlmsg_end(reply, hdr);
	return genlmsg_reply(reply, info);
nla_fail:
	nlmsg_free(reply);
	return -EMSGSIZE;
}

static int rayfw_list_rules(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(cb->skb->sk);
	struct rayfw_net *rnet = net_generic(net, rayfw_net_id);
	struct rayfw_ruleset *ruleset;
	struct rayfw_rule *rule;
	unsigned long skip = cb->args[0], index = 0;
	void *hdr;
	int chain;

	rcu_read_lock();
	ruleset = rcu_dereference(rnet->active);
	for (chain = 0; chain < RAYFW_CHAIN_MAX; chain++) {
		list_for_each_entry_rcu(rule, &ruleset->rules[chain], node) {
			struct rayfw_rule_wire spec;

			if (index++ < skip)
				continue;
			spec = rule->spec;
			spec.packets = atomic64_read(&rule->packets);
			spec.bytes = atomic64_read(&rule->bytes);
			hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid,
					  cb->nlh->nlmsg_seq, &rayfw_genl_family,
					  NLM_F_MULTI, RAYFW_CMD_LIST_RULES);
			if (!hdr || nla_put(skb, RAYFW_A_RULE, sizeof(spec), &spec)) {
				if (hdr)
					genlmsg_cancel(skb, hdr);
				goto out;
			}
			genlmsg_end(skb, hdr);
			cb->args[0]++;
		}
	}
out:
	rcu_read_unlock();
	return skb->len;
}

static int rayfw_reset_counters(struct sk_buff *skb, struct genl_info *info)
{
	struct rayfw_net *rnet = net_generic(genl_info_net(info), rayfw_net_id);
	struct rayfw_ruleset *ruleset;
	struct rayfw_rule *rule;
	int chain;

	mutex_lock(&rnet->lock);
	if (rnet->transaction) {
		mutex_unlock(&rnet->lock);
		return -EBUSY;
	}
	ruleset = rcu_dereference_protected(rnet->active, lockdep_is_held(&rnet->lock));
	for (chain = 0; chain < RAYFW_CHAIN_MAX; chain++) {
		list_for_each_entry(rule, &ruleset->rules[chain], node) {
			atomic64_set(&rule->packets, 0);
			atomic64_set(&rule->bytes, 0);
		}
	}
	mutex_unlock(&rnet->lock);
	return 0;
}

static void rayfw_tx_timeout(struct work_struct *work)
{
	struct rayfw_transaction *transaction = container_of(to_delayed_work(work),
		struct rayfw_transaction, timeout_work);
	struct rayfw_net *rnet = transaction->rnet;
	struct rayfw_ruleset *staged = NULL;

	mutex_lock(&rnet->lock);
	if (rnet->transaction == transaction) {
		rnet->transaction = NULL;
		staged = transaction->staged;
		transaction->staged = NULL;
	}
	mutex_unlock(&rnet->lock);
	if (staged) {
		pr_warn("rayfw: transaction %u timed out and was aborted\n", transaction->id);
		rayfw_ruleset_free(staged);
		kfree(transaction);
	}
}

static int rayfw_tx_begin(struct sk_buff *skb, struct genl_info *info)
{
	struct rayfw_net *rnet = net_generic(genl_info_net(info), rayfw_net_id);
	struct rayfw_transaction *transaction;
	struct rayfw_ruleset *staged;
	struct sk_buff *reply;
	void *hdr;
	struct nlattr *reply_attr;
	u32 *reply_id;

	reply = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;
	hdr = genlmsg_put_reply(reply, info, &rayfw_genl_family, 0,
				RAYFW_CMD_TX_BEGIN);
	if (!hdr || !(reply_attr = nla_reserve(reply, RAYFW_A_TX_ID, sizeof(*reply_id)))) {
		nlmsg_free(reply);
		return -EMSGSIZE;
	}
	reply_id = nla_data(reply_attr);
	transaction = kzalloc(sizeof(*transaction), GFP_KERNEL);
	if (!transaction) {
		nlmsg_free(reply);
		return -ENOMEM;
	}
	mutex_lock(&rnet->lock);
	if (rnet->transaction) {
		mutex_unlock(&rnet->lock);
		kfree(transaction);
		nlmsg_free(reply);
		return -EBUSY;
	}
	staged = rayfw_ruleset_clone(rcu_dereference_protected(rnet->active,
		lockdep_is_held(&rnet->lock)));
	if (!staged) {
		mutex_unlock(&rnet->lock);
		kfree(transaction);
		nlmsg_free(reply);
		return -ENOMEM;
	}
	if (!++rnet->next_transaction_id)
		++rnet->next_transaction_id;
	transaction->id = rnet->next_transaction_id;
	transaction->portid = info->snd_portid;
	transaction->rnet = rnet;
	transaction->staged = staged;
	INIT_DELAYED_WORK(&transaction->timeout_work, rayfw_tx_timeout);
	rnet->transaction = transaction;
	mutex_unlock(&rnet->lock);
	queue_delayed_work(system_wq, &transaction->timeout_work,
		msecs_to_jiffies(transaction_timeout_ms ?: 1));
	*reply_id = transaction->id;
	genlmsg_end(reply, hdr);
	return genlmsg_reply(reply, info);
}

static int rayfw_tx_finish(struct sk_buff *skb, struct genl_info *info, bool commit)
{
	struct rayfw_net *rnet = net_generic(genl_info_net(info), rayfw_net_id);
	struct rayfw_transaction *transaction;
	u32 id;

	if (!info->attrs[RAYFW_A_TX_ID])
		return -EINVAL;
	id = nla_get_u32(info->attrs[RAYFW_A_TX_ID]);
	mutex_lock(&rnet->lock);
	transaction = rnet->transaction;
	if (!transaction || transaction->id != id || transaction->portid != info->snd_portid) {
		mutex_unlock(&rnet->lock);
		return -EPERM;
	}
	rnet->transaction = NULL;
	if (commit)
		rayfw_publish_ruleset(rnet, transaction->staged);
	mutex_unlock(&rnet->lock);
	cancel_delayed_work_sync(&transaction->timeout_work);
	if (!commit)
		rayfw_ruleset_free(transaction->staged);
	kfree(transaction);
	return 0;
}

static int rayfw_tx_commit(struct sk_buff *skb, struct genl_info *info)
{
	return rayfw_tx_finish(skb, info, true);
}

static int rayfw_tx_abort(struct sk_buff *skb, struct genl_info *info)
{
	return rayfw_tx_finish(skb, info, false);
}

static const struct genl_ops rayfw_genl_ops[] = {
	{
		.cmd = RAYFW_CMD_ADD_RULE,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_add_rule,
	},
	{
		.cmd = RAYFW_CMD_DELETE_RULE,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_delete_rule,
	},
	{
		.cmd = RAYFW_CMD_FLUSH_RULES,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_flush_rules,
	},
	{
		.cmd = RAYFW_CMD_SET_POLICY,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_set_policy,
	},
	{
		.cmd = RAYFW_CMD_SET_ENABLED,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_set_enabled,
	},
	{
		.cmd = RAYFW_CMD_GET_STATUS,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_get_status,
	},
	{
		.cmd = RAYFW_CMD_LIST_RULES,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.dumpit = rayfw_list_rules,
	},
	{
		.cmd = RAYFW_CMD_RESET_COUNTERS,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_reset_counters,
	},
	{
		.cmd = RAYFW_CMD_TX_BEGIN,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_tx_begin,
	},
	{
		.cmd = RAYFW_CMD_TX_COMMIT,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_tx_commit,
	},
	{
		.cmd = RAYFW_CMD_TX_ABORT,
		.flags = GENL_ADMIN_PERM,
		.policy = rayfw_nla_policy,
		.doit = rayfw_tx_abort,
	},
};

static struct genl_family rayfw_genl_family = {
	.name = RAYFW_GENL_NAME,
	.version = RAYFW_GENL_VERSION,
	.maxattr = RAYFW_A_MAX,
	.netnsok = true,
	.module = THIS_MODULE,
	.ops = rayfw_genl_ops,
	.n_ops = ARRAY_SIZE(rayfw_genl_ops),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	.resv_start_op = RAYFW_CMD_MAX + 1,
#endif
};

static int __net_init rayfw_net_init(struct net *net)
{
	struct rayfw_net *rnet = net_generic(net, rayfw_net_id);
	struct rayfw_ruleset *ruleset;
	static const u8 chains[3] = {
		RAYFW_CHAIN_INPUT, RAYFW_CHAIN_OUTPUT, RAYFW_CHAIN_FORWARD
	};
	static const unsigned int hooknums[3] = {
		NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_FORWARD
	};
	int family, i, n = 0;

	mutex_init(&rnet->lock);
	ruleset = rayfw_ruleset_alloc();
	if (!ruleset)
		return -ENOMEM;
	RCU_INIT_POINTER(rnet->active, ruleset);
	for (family = 0; family < 2; family++) {
		for (i = 0; i < 3; i++, n++) {
			rnet->contexts[n].rnet = rnet;
			rnet->contexts[n].chain = chains[i];
			rnet->hooks[n].hook = rayfw_hook;
			rnet->hooks[n].priv = &rnet->contexts[n];
			rnet->hooks[n].pf = family ? NFPROTO_IPV6 : NFPROTO_IPV4;
			rnet->hooks[n].hooknum = hooknums[i];
			rnet->hooks[n].priority = NF_IP_PRI_FILTER;
		}
	}
	{
		int err = nf_register_net_hooks(net, rnet->hooks, ARRAY_SIZE(rnet->hooks));

		if (!err)
			return 0;
		rayfw_ruleset_free(ruleset);
		RCU_INIT_POINTER(rnet->active, NULL);
		return err;
	}
}

static void __net_exit rayfw_net_exit(struct net *net)
{
	struct rayfw_net *rnet = net_generic(net, rayfw_net_id);
	struct rayfw_ruleset *ruleset;
	struct rayfw_transaction *transaction;

	nf_unregister_net_hooks(net, rnet->hooks, ARRAY_SIZE(rnet->hooks));
	mutex_lock(&rnet->lock);
	ruleset = rcu_dereference_protected(rnet->active, lockdep_is_held(&rnet->lock));
	transaction = rnet->transaction;
	rnet->transaction = NULL;
	RCU_INIT_POINTER(rnet->active, NULL);
	mutex_unlock(&rnet->lock);
	if (transaction) {
		cancel_delayed_work_sync(&transaction->timeout_work);
		rayfw_ruleset_free(transaction->staged);
		kfree(transaction);
	}
	synchronize_rcu();
	rayfw_ruleset_free(ruleset);
}

static struct pernet_operations rayfw_pernet_ops = {
	.init = rayfw_net_init,
	.exit = rayfw_net_exit,
	.id = &rayfw_net_id,
	.size = sizeof(struct rayfw_net),
};

static int __init rayfw_init(void)
{
	int err;

	err = register_pernet_subsys(&rayfw_pernet_ops);
	if (err)
		return err;
	err = genl_register_family(&rayfw_genl_family);
	if (err) {
		unregister_pernet_subsys(&rayfw_pernet_ops);
		return err;
	}
	pr_info("rayfw: version %s loaded\n", RAYFW_VERSION);
	return 0;
}

static void __exit rayfw_exit(void)
{
	genl_unregister_family(&rayfw_genl_family);
	unregister_pernet_subsys(&rayfw_pernet_ops);
	rcu_barrier();
	pr_info("rayfw: unloaded\n");
}

module_init(rayfw_init);
module_exit(rayfw_exit);

MODULE_AUTHOR("rainyxin");
MODULE_DESCRIPTION("RayFireWall Netfilter firewall");
MODULE_LICENSE("GPL");
MODULE_VERSION(RAYFW_VERSION);
