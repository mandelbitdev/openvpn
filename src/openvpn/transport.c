#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "error.h"
#include "plugin.h"
#include "transport.h"
#include "openvpn-vsocket.h"

bool find_indirect_vtab(const struct plugin_list *plugins,
                        const char **transport_plugin_argv,
                        struct openvpn_vsocket_vtab **vtabp,
                        openvpn_plugin_handle_t *handlep)
{
    int i, n;
    const char *expected_so_pathname = transport_plugin_argv[0];

    n = plugins->common->n;
    for (i = 0; i < n; i++)
    {
        struct plugin *p = &plugins->common->plugins[i];
        if (p->so_pathname && !strcmp(p->so_pathname, expected_so_pathname))
        {
            /* Pathname matches; this is the plugin requested. */
            if (!(p->plugin_type_mask & OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_SOCKET_INTERCEPT)))
            {
                msg(M_FATAL, "INDIRECT: plugin %s does not indicate SOCKET_INTERCEPT functionality",
                    p->so_pathname);
            }

            /* TODO: add defensive magic number to beginning of struct? */
            size_t size;
            struct openvpn_vsocket_vtab *vtab =
                p->get_vtab ? p->get_vtab(OPENVPN_VTAB_SOCKET_INTERCEPT_SOCKET_V1, &size)
                : NULL;
            if (!vtab)
            {
                msg(M_FATAL, "INDIRECT: plugin %s has no SOCKET_INTERCEPT_SOCKET_V1 table",
                    p->so_pathname);
            }

            if (size != sizeof(struct openvpn_vsocket_vtab))
            {
                /* TODO: check for non-NULL function pointers as needed too */
                msg(M_FATAL, "INDIRECT: plugin %s returned a faulty SOCKET_INTERCEPT_SOCKET_V1 table",
                    p->so_pathname);
            }

            *vtabp = vtab;
            *handlep = p->plugin_handle;
            return true;
        }
    }

    return false;
}
