#ifndef OPENVPN_TRANSPORT_H
#define OPENVPN_TRANSPORT_H

#ifdef ENABLE_PLUGIN

#include "plugin.h"
#include "openvpn-transport.h"

/* Given a list of plugins and an argument list for a desired
 * transport plugin instance, prepare to bind new link sockets using
 * that transport plugin and args. If all succeeds, return true, and:
 *
 *   *vtabp is set to the vtable by which to bind new link sockets.
 *   *handlep is set to the plugin handle to use in bind calls.
 *   *argsp is set to the args value to use in bind calls. It is
 *     the caller's responsibility to call freeargs on it later.
 *
 * Otherwise, return false, and the values of all of the above are
 * undefined. None of the output pointers may be NULL.
 */
bool transport_prepare(const struct plugin_list *plugins,
                       const char **transport_plugin_argv,
                       struct openvpn_transport_bind_vtab1 **vtabp,
                       openvpn_plugin_handle_t *handlep,
                       openvpn_transport_args_t *argsp);

#endif /* ENABLE_PLUGIN */

#endif /* !OPENVPN_TRANSPORT_H */
