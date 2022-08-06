
#include <sys/socket.h>
#include <netinet/in.h>

#include <string.h>

#include "got_sockaddr.h"

/* These calls are found in lib/socketaddr.c, but are overriden here for
 * platform-specific reasons.
 */

void
got_sockaddr_inet_init(struct sockaddr_in *in, struct in_addr *ina)
{
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = ina->s_addr;
}

void
got_sockaddr_inet6_init(struct sockaddr_in6 *in6, struct in6_addr *in6a,
    uint32_t sin6_scope_id)
{
	in6->sin6_family = AF_INET6;
	memcpy(&in6->sin6_addr, in6a, sizeof(in6->sin6_addr));
	in6->sin6_scope_id = sin6_scope_id;
}
