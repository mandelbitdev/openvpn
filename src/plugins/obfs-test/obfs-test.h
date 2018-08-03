#ifndef OPENVPN_PLUGIN_OBFS_TEST_H
#define OPENVPN_PLUGIN_OBFS_TEST_H 1

#include "openvpn-plugin.h"
#include "openvpn-transport.h"

#define OBFS_TEST_PLUGIN_NAME "obfs-test"

struct obfs_test_context;
extern struct openvpn_transport_bind_vtab1 obfs_test_bind_vtab;
extern struct openvpn_transport_socket_vtab1 obfs_test_socket_vtab;
void obfs_test_initialize_vtabs(void);
void obfs_test_munge_addr(struct sockaddr *addr, openvpn_transport_socklen_t len);
size_t obfs_test_max_munged_buf_size(size_t clear_size);
size_t obfs_test_munge_buf(char *out, const char *in, size_t len);
ssize_t obfs_test_unmunge_buf(char *buf, size_t len);
void obfs_test_log(struct obfs_test_context *ctx,
                   openvpn_plugin_log_flags_t flags, const char *fmt, ...);

#endif /* !OPENVPN_PLUGIN_OBFS_TEST_H */
