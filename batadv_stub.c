#include "alfred.h"
#include "batadv_query.h"

#include <errno.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <string.h>

int mac_to_ipv6(const struct ether_addr *mac, alfred_addr *addr)
{
    memset(addr, 0, sizeof(*addr));
    addr->ipv6.s6_addr[0] = 0xfe;
    addr->ipv6.s6_addr[1] = 0x80;

    addr->ipv6.s6_addr[8] = mac->ether_addr_octet[0] ^ 0x02;
    addr->ipv6.s6_addr[9] = mac->ether_addr_octet[1];
    addr->ipv6.s6_addr[10] = mac->ether_addr_octet[2];

    addr->ipv6.s6_addr[11] = 0xff;
    addr->ipv6.s6_addr[12] = 0xfe;

    addr->ipv6.s6_addr[13] = mac->ether_addr_octet[3];
    addr->ipv6.s6_addr[14] = mac->ether_addr_octet[4];
    addr->ipv6.s6_addr[15] = mac->ether_addr_octet[5];

    return 0;
}

int is_ipv6_eui64(const struct in6_addr *addr)
{
    size_t i;

    for (i = 2; i < 8; i++) {
        if (addr->s6_addr[i] != 0x0)
            return 0;
    }

    if (addr->s6_addr[0] != 0xfe ||
        addr->s6_addr[1] != 0x80 ||
        addr->s6_addr[11] != 0xff ||
        addr->s6_addr[12] != 0xfe)
        return 0;

    return 1;
}

int ipv6_to_mac(const alfred_addr *addr, struct ether_addr *mac)
{
    if (!is_ipv6_eui64(&addr->ipv6))
        return -EINVAL;

    mac->ether_addr_octet[0] = addr->ipv6.s6_addr[8] ^ 0x02;
    mac->ether_addr_octet[1] = addr->ipv6.s6_addr[9];
    mac->ether_addr_octet[2] = addr->ipv6.s6_addr[10];
    mac->ether_addr_octet[3] = addr->ipv6.s6_addr[13];
    mac->ether_addr_octet[4] = addr->ipv6.s6_addr[14];
    mac->ether_addr_octet[5] = addr->ipv6.s6_addr[15];

    if (!is_valid_ether_addr(mac->ether_addr_octet))
        return -EINVAL;

    return 0;
}

int ipv4_to_mac(struct interface *interface,
                const alfred_addr *addr, struct ether_addr *mac)
{
    if (ipv4_arp_request(interface, addr, mac) < 0)
        return -EINVAL;

    if (!is_valid_ether_addr(mac->ether_addr_octet))
        return -EINVAL;

    return 0;
}

int batadv_interface_check(const char *mesh_iface)
{
    (void)mesh_iface;
    errno = ENOSYS;
    return -1;
}

struct hashtable_t *tg_hash_new(const char *mesh_iface)
{
    (void)mesh_iface;
    return NULL;
}

void tg_hash_free(struct hashtable_t *tg_hash)
{
    (void)tg_hash;
}

int tg_hash_add(struct hashtable_t *tg_hash, struct ether_addr *mac,
                struct ether_addr *originator)
{
    (void)tg_hash;
    (void)mac;
    (void)originator;
    return 0;
}

struct ether_addr *translate_mac(struct hashtable_t *tg_hash,
                                 const struct ether_addr *mac)
{
    (void)tg_hash;
    (void)mac;
    return NULL;
}

struct hashtable_t *orig_hash_new(const char *mesh_iface)
{
    (void)mesh_iface;
    return NULL;
}

void orig_hash_free(struct hashtable_t *orig_hash)
{
    (void)orig_hash;
}

int orig_hash_add(struct hashtable_t *orig_hash, struct ether_addr *mac,
                  uint8_t tq)
{
    (void)orig_hash;
    (void)mac;
    (void)tq;
    return 0;
}

uint8_t get_tq(struct hashtable_t *orig_hash, struct ether_addr *mac)
{
    (void)orig_hash;
    (void)mac;
    return 0;
}
