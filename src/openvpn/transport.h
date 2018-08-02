#ifndef OPENVPN_TRANSPORT_H
#define OPENVPN_TRANSPORT_H

#include "plugin.h"
#include "openvpn-vsocket.h"

/* Given a list of plugins and an argument list for a desired
 * transport plugin instance, prepare to bind new link sockets using
 * that transport plugin and args. If all succeeds, return true, and:
 *
 *   *vtabp is set to the vtable by which to bind transport plugins.
 *   *handlep is set to the plugin handle to use in bind calls.
 *
 * Otherwise, return false, and the values of all of the above are
 * undefined. None of the output pointers may be NULL.
 */
bool find_indirect_vtab(const struct plugin_list *plugins,
                        const char **transport_plugin_argv,
                        struct openvpn_vsocket_vtab **vtabp,
                        openvpn_plugin_handle_t *handlep);

#endif /* !OPENVPN_TRANSPORT_H */
