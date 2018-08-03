#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef ENABLE_PLUGIN

#include "error.h"
#include "plugin.h"
#include "socket.h"
#include "transport.h"
#include "openvpn-transport.h"

bool transport_prepare(const struct plugin_list *plugins,
                       const char **transport_plugin_argv,
                       struct openvpn_transport_bind_vtab1 **vtabp,
                       openvpn_plugin_handle_t *handlep,
                       openvpn_transport_args_t *argsp)
{
    const char *expected_so_pathname = transport_plugin_argv[0];
    int argc = 0;
    while (transport_plugin_argv[argc])
        argc++;

    for (int i = 0; i < plugins->common->n; i++)
    {
        struct plugin *p = &plugins->common->plugins[i];
        if (p->so_pathname && !strcmp(p->so_pathname, expected_so_pathname))
        {
            /* Pathname matches; this is the plugin requested. */
            if (!(p->plugin_type_mask & OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_TRANSPORT)))
            {
                msg(M_FATAL, "INDIRECT: plugin %s does not indicate TRANSPORT functionality",
                    p->so_pathname);
            }

            size_t size;
            struct openvpn_transport_bind_vtab1 *vtab =
                p->get_vtab ? p->get_vtab(OPENVPN_VTAB_TRANSPORT_BIND_V1, &size)
                : NULL;
            if (!vtab)
            {
                msg(M_FATAL, "INDIRECT: plugin %s has no TRANSPORT_BIND_V1 table",
                    p->so_pathname);
            }

            /* Sanity checks on the vtable. */
            if (!(size == sizeof(*vtab)
                  && vtab->bind
                  && ((vtab->parseargs && vtab->argerror && vtab->freeargs)
                      || (!vtab->parseargs && !vtab->argerror && !vtab->freeargs))))
            {
                msg(M_FATAL, "INDIRECT: plugin %s returned a faulty TRANSPORT_BIND_V1 table",
                    p->so_pathname);
            }

            openvpn_transport_args_t args = NULL;
            if (vtab->parseargs)
            {
                args = vtab->parseargs(p->plugin_handle, transport_plugin_argv, argc);
                const char *argerror = vtab->argerror(args);
                if (argerror)
                {
                    msg(M_FATAL, "INDIRECT: invalid arguments to transport-plugin %s: %s",
                        p->so_pathname, argerror);
                }
            }

            *vtabp = vtab;
            *handlep = p->plugin_handle;
            *argsp = args;
            return true;
        }
    }

    return false;
}

openvpn_transport_socket_t
transport_bind(const struct plugin_list *plugins,
               const char **transport_plugin_argv,
               sa_family_t ai_family,
               struct addrinfo *bind_addresses)
{
    openvpn_plugin_handle_t handle;
    openvpn_transport_args_t args;
    openvpn_transport_socket_t indirect;
    struct openvpn_transport_bind_vtab1 *vtab;
    struct addrinfo *cur = NULL;
    struct openvpn_sockaddr zero;

    if (!transport_prepare(plugins, transport_plugin_argv,
                           &vtab, &handle, &args))
        msg(M_FATAL, "INDIRECT: Socket bind failed: provider plugin not found");

    /* Partially replicates the functionality of socket_bind. No bind_ipv6_only
       or other such options, presently. */
    if (bind_addresses)
    {
        for (cur = bind_addresses; cur; cur = cur->ai_next)
        {
            if (cur->ai_family == ai_family)
            {
                break;
            }
        }

        if (!cur)
        {
            msg(M_FATAL, "INDIRECT: Socket bind failed: Addr to bind has no %s record",
                addr_family_name(ai_family));
        }
    }

    if (cur)
    {
        indirect = vtab->bind(handle, args, cur->ai_addr, cur->ai_addrlen);
    }
    else if (ai_family == AF_UNSPEC)
    {
        msg(M_ERR, "INDIRECT: cannot bind with unspecified address family");
    }
    else
    {
        memset(&zero, 0, sizeof(zero));
        zero.addr.sa.sa_family = ai_family;
        addr_zero_host(&zero);
        indirect = vtab->bind(handle, args, &zero.addr.sa, af_addr_size(ai_family));
    }

    if (!indirect)
        msg(M_ERR, "INDIRECT: Socket bind failed");
    if (vtab->freeargs)
        vtab->freeargs(args);
    return indirect;
}

#endif  /* ENABLE_PLUGIN */
