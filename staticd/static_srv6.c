// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - Segment Routing over IPv6 (SRv6) code
 */
#include <zebra.h>

#include "vrf.h"
#include "nexthop.h"

#include "static_routes.h"
#include "static_srv6.h"
#include "static_vrf.h"
#include "static_zebra.h"

/*
 * List of SRv6 SIDs.
 */
struct list *srv6_locators = NULL;
struct list *srv6_sids = NULL;

DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_LOCATOR, "Static SRv6 locator");
DEFINE_MTYPE_STATIC(STATIC, STATIC_SRV6_SID, "Static SRv6 SID");

/*
 * Convert SRv6 behavior to human-friendly string.
 */
const char *
static_srv6_sid_behavior2str(enum static_srv6_sid_behavior_t behavior)
{
	switch (behavior) {
	case STATIC_SRV6_SID_BEHAVIOR_END:
		return "End";
	case STATIC_SRV6_SID_BEHAVIOR_END_X:
		return "End.X";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT6:
		return "End.DT6";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT4:
		return "End.DT4";
	case STATIC_SRV6_SID_BEHAVIOR_END_DT46:
		return "End.DT46";
	case STATIC_SRV6_SID_BEHAVIOR_UN:
		return "uN";
	case STATIC_SRV6_SID_BEHAVIOR_UA:
		return "uA";
	case STATIC_SRV6_SID_BEHAVIOR_UDT6:
		return "uDT6";
	case STATIC_SRV6_SID_BEHAVIOR_UDT4:
		return "uDT4";
	case STATIC_SRV6_SID_BEHAVIOR_UDT46:
		return "uDT46";
	case STATIC_SRV6_SID_BEHAVIOR_UNSPEC:
		return "unspec";
	}

	return "unspec";
}

/*
 * When an interface is enabled in the kernel, go through all the static SRv6 SIDs in
 * the system that use this interface and install/remove them in the zebra RIB.
 *
 * ifp   - The interface being enabled
 * is_up - Whether the interface is up or down
 */
void static_ifp_srv6_sids_update(struct interface *ifp, bool is_up)
{
	struct static_srv6_locator *locator;
	struct static_srv6_sid *sid;
	struct listnode *node;

	if (!srv6_sids || !ifp)
		return;

	zlog_info("Interface %s %s. %s SIDs that depend on the interface", (is_up) ? "enabled" : "disabled", (is_up) ? "Removing" : "disabled", ifp->name);

    /* iterate over the list of SRv6 SIDs and remove the SIDs that use this
    * VRF from the zebra RIB */
    for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
        if (strcmp(sid->attributes.vrf_name, ifp->name) == 0 ||
                strncmp(ifp->name, "sr0", sizeof(ifp->name)) == 0 &&
                (sid->behavior == STATIC_SRV6_SID_BEHAVIOR_END || sid->behavior == STATIC_SRV6_SID_BEHAVIOR_UN))
            if (is_up)
                static_zebra_srv6_sid_install(sid);
            else
                static_zebra_srv6_sid_uninstall(sid);
    }
}

/*
 * Allocate an SRv6 SID object and initialize the fields common to all the
 * behaviors (i.e., SID address and behavor).
 */
struct static_srv6_sid *static_srv6_sid_alloc(struct prefix_ipv6 *addr)
{
	struct static_srv6_sid *sid = NULL;

	sid = XCALLOC(MTYPE_STATIC_SRV6_SID, sizeof(struct static_srv6_sid));
	sid->addr = *addr;

	return sid;
}

void static_srv6_sid_free(struct static_srv6_sid *sid)
{
	XFREE(MTYPE_STATIC_SRV6_SID, sid);
}

struct static_srv6_locator *static_srv6_locator_lookup(const char *name)
{
	struct static_srv6_locator *locator;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node, locator))
		if (!strncmp(name, locator->name, SRV6_LOCNAME_SIZE))
			return locator;
	return NULL;
}

/*
 * Look-up an SRv6 SID in the list of SRv6 SIDs.
 */
struct static_srv6_sid *static_srv6_sid_lookup(struct prefix_ipv6 *sid_addr)
{
	struct static_srv6_locator *locator;
	struct static_srv6_sid *sid;
	struct listnode *node1, *node2;

	for (ALL_LIST_ELEMENTS_RO(srv6_locators, node1, locator))
		for (ALL_LIST_ELEMENTS_RO(srv6_sids, node2, sid))
			if (memcmp(&sid->addr, sid_addr, sizeof(struct prefix_ipv6)) == 0)
				return sid;

	return NULL;
}

struct static_srv6_locator *static_srv6_locator_alloc(const char *name)
{
	struct static_srv6_locator *locator = NULL;

	locator = XCALLOC(MTYPE_STATIC_SRV6_LOCATOR, sizeof(struct static_srv6_locator));
	strlcpy(locator->name, name, sizeof(locator->name));

	return locator;
}

void static_srv6_locator_free(struct static_srv6_locator *locator)
{
	if (locator) {
		XFREE(MTYPE_STATIC_SRV6_LOCATOR, locator);
	}
}

void delete_static_srv6_locator(void *val)
{
	static_srv6_locator_free((struct static_srv6_locator *)val);
}

/*
 * Remove an SRv6 SID from the zebra RIB (if it was previously installed) and
 * release the memory previously allocated for the SID.
 */
void static_srv6_sid_del(struct static_srv6_sid *sid)
{
	// if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_release_srv6_sid(sid);
		static_zebra_srv6_sid_uninstall(sid);

	XFREE(MTYPE_STATIC_SRV6_SID, sid);
}

void delete_static_srv6_sid(void *val)
{
	static_srv6_sid_free((struct static_srv6_sid *)val);
}

/*
 * Initialize SRv6 data structures.
 */
void static_srv6_init(void)
{
	srv6_locators = list_new();
	srv6_sids = list_new();
}

/*
 * Clean up all the SRv6 data structures.
 */
void static_srv6_cleanup(void)
{
	list_delete(&srv6_locators);
	list_delete(&srv6_sids);
}