#include "binding.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "alfred/alfred.h"
#include "alfred/list.h"
#include "alfred/hash.h"
#include "alfred/packet.h"

struct go_alfred_client {
    struct globals *globals;
};

struct go_alfred_server {
    struct globals *globals;
    pthread_t thread;
    int running;
};

static int test_fd_override = -1;

static int go_set_error(char **err_out, const char *fmt, ...)
{
    va_list args;

    if (!err_out)
        return 0;

    va_start(args, fmt);
    if (vasprintf(err_out, fmt, args) < 0)
        *err_out = NULL;
    va_end(args);

    return 0;
}

static void go_seed_random(void)
{
    static bool seeded = false;

    if (seeded)
        return;

    seeded = true;
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
}

static uint16_t go_random_id(void)
{
    go_seed_random();
    return (uint16_t)(rand() & 0xffff);
}

static ssize_t go_read_exact(int fd, unsigned char *buf, size_t len)
{
    size_t total = 0;

    while (total < len) {
        ssize_t ret = read(fd, buf + total, len - total);

        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (ret == 0)
            return (ssize_t)total;

        total += (size_t)ret;
    }

    return (ssize_t)total;
}

static ssize_t go_write_exact(int fd, const unsigned char *buf, size_t len)
{
    size_t total = 0;

    while (total < len) {
        ssize_t ret = write(fd, buf + total, len - total);

        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        total += (size_t)ret;
    }

    return (ssize_t)total;
}

static int go_unix_sock_open_client(struct globals *globals, char **err_out)
{
    struct sockaddr_un addr;

    if (globals->unix_path && strcmp(globals->unix_path, ":test:") == 0) {
        if (test_fd_override < 0) {
            go_set_error(err_out, "no test socket registered");
            return -1;
        }

        globals->unix_sock = test_fd_override;
        test_fd_override = -1;
        return 0;
    }

    globals->unix_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (globals->unix_sock < 0)
        return go_set_error(err_out, "cannot create unix socket: %s", strerror(errno)), -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (globals->unix_path)
        strncpy(addr.sun_path, globals->unix_path, sizeof(addr.sun_path) - 1);

    if (connect(globals->unix_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int saved = errno;

        close(globals->unix_sock);
        globals->unix_sock = -1;

        return go_set_error(err_out, "connect(%s): %s",
                            globals->unix_path ? globals->unix_path : "<nil>",
                            strerror(saved)), -1;
    }

    return 0;
}

static void go_unix_sock_close(struct globals *globals)
{
    if (!globals)
        return;

    if (globals->unix_sock >= 0) {
        close(globals->unix_sock);
        globals->unix_sock = -1;
    }
}

go_alfred_client *go_alfred_client_new(const char *unix_path, int verbose, int ipv4_mode)
{
    go_alfred_client *client;
    struct globals *globals;

    client = calloc(1, sizeof(*client));
    if (!client)
        return NULL;

    globals = calloc(1, sizeof(*globals));
    if (!globals) {
        free(client);
        return NULL;
    }

    INIT_LIST_HEAD(&globals->interfaces);
    INIT_LIST_HEAD(&globals->event_listeners);
    globals->net_iface = NULL;
    globals->best_server = NULL;
    globals->mesh_iface = NULL;
    globals->opmode = OPMODE_SECONDARY;
    globals->clientmode = CLIENT_NONE;
    globals->clientmode_arg = 0;
    globals->clientmode_version = 0;
    globals->verbose = verbose ? 1 : 0;
    globals->ipv4mode = ipv4_mode ? 1 : 0;
    globals->force = 0;
    globals->epollfd = -1;
    globals->check_timerfd = -1;
    globals->unix_sock = -1;
    globals->unix_path = unix_path ? strdup(unix_path) : strdup(ALFRED_SOCK_PATH_DEFAULT);
    globals->update_command = NULL;
    bitmap_zero(globals->changed_data_types, ALFRED_NUM_TYPES);
    globals->data_hash = NULL;
    globals->transaction_hash = NULL;

    if (!globals->unix_path) {
        free(globals);
        free(client);
        return NULL;
    }

    client->globals = globals;
    return client;
}

void go_alfred_client_free(go_alfred_client *client)
{
    if (!client)
        return;

    if (client->globals) {
        go_unix_sock_close(client->globals);
        if (client->globals->unix_path)
            free((void *)client->globals->unix_path);
        free(client->globals);
    }

    free(client);
}

int go_alfred_client_request(go_alfred_client *client, uint8_t data_type,
                             go_alfred_record **records_out, size_t *count_out,
                             char **err_out)
{
    unsigned char buf[MAX_PAYLOAD];
    struct alfred_push_data_v0 *push = (struct alfred_push_data_v0 *)buf;
    struct alfred_tlv *tlv = (struct alfred_tlv *)buf;
    go_alfred_record *records = NULL;
    size_t count = 0;
    size_t capacity = 0;
    int result = -1;

    if (records_out)
        *records_out = NULL;
    if (count_out)
        *count_out = 0;
    if (err_out)
        *err_out = NULL;

    if (!client || !client->globals || !records_out || !count_out)
        return go_set_error(err_out, "invalid client or output arguments"), -1;

    client->globals->clientmode_arg = data_type;

    if (go_unix_sock_open_client(client->globals, err_out))
        return -1;

    struct alfred_request_v0 request;

    memset(&request, 0, sizeof(request));
    request.header.type = ALFRED_REQUEST;
    request.header.version = ALFRED_VERSION;
    request.header.length = FIXED_TLV_LEN(request);
    request.requested_type = data_type;
    request.tx_id = go_random_id();

    if (go_write_exact(client->globals->unix_sock, (unsigned char *)&request,
                       sizeof(request)) < (ssize_t)sizeof(request)) {
        go_set_error(err_out, "failed to write request: %s", strerror(errno));
        goto out;
    }

    for (;;) {
        ssize_t read_len;

        read_len = go_read_exact(client->globals->unix_sock, buf, sizeof(*tlv));
        if (read_len == 0)
            break;
        if (read_len < 0) {
            go_set_error(err_out, "failed to read response header: %s", strerror(errno));
            goto out;
        }
        if (read_len < (ssize_t)sizeof(*tlv)) {
            go_set_error(err_out, "short read on tlv header");
            goto out;
        }

        if (tlv->type == ALFRED_STATUS_ERROR) {
            struct alfred_status_v0 *status = (struct alfred_status_v0 *)buf;

            read_len = go_read_exact(client->globals->unix_sock,
                                     buf + sizeof(*tlv),
                                     sizeof(*status) - sizeof(*tlv));
            if (read_len < (ssize_t)(sizeof(*status) - sizeof(*tlv))) {
                go_set_error(err_out, "short read on status payload");
                goto out;
            }

            go_set_error(err_out, "alfred server returned error %u", status->tx.seqno);
            goto out;
        }

        if (tlv->type != ALFRED_PUSH_DATA)
            break;

        read_len = go_read_exact(client->globals->unix_sock,
                                 buf + sizeof(*tlv),
                                 sizeof(*push) - sizeof(*tlv));
        if (read_len < (ssize_t)(sizeof(*push) - sizeof(*tlv))) {
            go_set_error(err_out, "short read on push header");
            goto out;
        }

        read_len = go_read_exact(client->globals->unix_sock,
                                 buf + sizeof(*push),
                                 sizeof(struct alfred_data));
        if (read_len < (ssize_t)sizeof(struct alfred_data)) {
            go_set_error(err_out, "short read on data header");
            goto out;
        }

        struct alfred_data *data = push->data;
        int data_len = ntohs(data->header.length);
        size_t max_len = sizeof(buf) - sizeof(*push) - sizeof(struct alfred_data);

        if (data_len < 0 || (size_t)data_len > max_len) {
            go_set_error(err_out, "received invalid data length %d", data_len);
            goto out;
        }

        read_len = go_read_exact(client->globals->unix_sock,
                                 buf + sizeof(*push) + sizeof(struct alfred_data),
                                 (size_t)data_len);
        if (read_len < data_len) {
            go_set_error(err_out, "short read on data payload");
            goto out;
        }

        if (count == capacity) {
            size_t new_capacity = capacity ? capacity * 2 : 4;
            go_alfred_record *tmp = realloc(records, new_capacity * sizeof(*tmp));

            if (!tmp) {
                go_set_error(err_out, "out of memory");
                goto out;
            }

            records = tmp;
            capacity = new_capacity;
        }

        records[count].data = NULL;
        records[count].data_len = (size_t)data_len;
        records[count].version = data->header.version;
        memcpy(records[count].source, data->source, ETH_ALEN);

        if (data_len > 0) {
            records[count].data = malloc((size_t)data_len);
            if (!records[count].data) {
                go_set_error(err_out, "out of memory");
                goto out;
            }

            memcpy(records[count].data,
                   buf + sizeof(*push) + sizeof(struct alfred_data),
                   (size_t)data_len);
        }

        count++;
    }

    result = 0;

out:
    go_unix_sock_close(client->globals);

    if (result == 0) {
        *records_out = records;
        *count_out = count;
    } else {
        if (records) {
            for (size_t i = 0; i < count; i++)
                free(records[i].data);
            free(records);
        }
    }

    return result;
}

void go_alfred_client_free_records(go_alfred_record *records, size_t count)
{
    if (!records)
        return;

    for (size_t i = 0; i < count; i++)
        free(records[i].data);

    free(records);
}

int go_alfred_client_set(go_alfred_client *client, uint8_t data_type, uint16_t version,
                         const uint8_t *payload, size_t payload_len, char **err_out)
{
    unsigned char *buf;
    size_t header_len = sizeof(struct alfred_push_data_v0);
    size_t data_hdr_len = sizeof(struct alfred_data);
    size_t total_len;
    int result = -1;

    if (err_out)
        *err_out = NULL;

    if (!client || !client->globals)
        return go_set_error(err_out, "invalid client"), -1;

    total_len = header_len + data_hdr_len + payload_len;
    if (total_len > MAX_PAYLOAD)
        return go_set_error(err_out, "payload too large"), -1;

    buf = malloc(total_len);
    if (!buf)
        return go_set_error(err_out, "out of memory"), -1;

    struct alfred_push_data_v0 *push = (struct alfred_push_data_v0 *)buf;
    struct alfred_data *data = (struct alfred_data *)(buf + header_len);

    memset(push, 0, header_len + data_hdr_len);
    push->header.type = ALFRED_PUSH_DATA;
    push->header.version = ALFRED_VERSION;
    push->header.length = htons((uint16_t)(total_len - sizeof(push->header)));
    push->tx.id = go_random_id();
    push->tx.seqno = htons(0);

    memset(data->source, 0, sizeof(data->source));
    data->header.type = data_type;
    data->header.version = (uint8_t)version;
    data->header.length = htons((uint16_t)payload_len);

    if (payload_len > 0)
        memcpy(data->data, payload, payload_len);

    if (go_unix_sock_open_client(client->globals, err_out))
        goto out;

    if (go_write_exact(client->globals->unix_sock, buf, total_len) < (ssize_t)total_len) {
        go_set_error(err_out, "failed to send data: %s", strerror(errno));
        goto out;
    }

    result = 0;

out:
    go_unix_sock_close(client->globals);
    free(buf);
    return result;
}
int go_alfred_client_modeswitch(go_alfred_client *client, uint8_t mode, char **err_out)
{
    struct alfred_modeswitch_v0 modeswitch;
    int result = -1;

    if (err_out)
        *err_out = NULL;

    if (!client || !client->globals)
        return go_set_error(err_out, "invalid client"), -1;

    if (mode != ALFRED_MODESWITCH_SECONDARY && mode != ALFRED_MODESWITCH_PRIMARY)
        return go_set_error(err_out, "invalid mode"), -1;

    memset(&modeswitch, 0, sizeof(modeswitch));
    modeswitch.header.type = ALFRED_MODESWITCH;
    modeswitch.header.version = ALFRED_VERSION;
    modeswitch.header.length = FIXED_TLV_LEN(modeswitch);
    modeswitch.mode = mode;

    if (go_unix_sock_open_client(client->globals, err_out))
        return -1;

    if (go_write_exact(client->globals->unix_sock, (unsigned char *)&modeswitch,
                       sizeof(modeswitch)) < (ssize_t)sizeof(modeswitch)) {
        go_set_error(err_out, "failed to send mode switch: %s", strerror(errno));
        goto out;
    }

    if (mode == ALFRED_MODESWITCH_PRIMARY)
        client->globals->opmode = OPMODE_PRIMARY;
    else
        client->globals->opmode = OPMODE_SECONDARY;

    result = 0;

out:
    go_unix_sock_close(client->globals);
    return result;
}

int go_alfred_client_change_interface(go_alfred_client *client, const char *ifaces, char **err_out)
{
    struct alfred_change_interface_v0 change_interface;
    size_t length;
    int result = -1;

    if (err_out)
        *err_out = NULL;

    if (!client || !client->globals)
        return go_set_error(err_out, "invalid client"), -1;

    if (!ifaces || !ifaces[0])
        return go_set_error(err_out, "interface list must not be empty"), -1;

    length = strlen(ifaces);
    if (length >= sizeof(change_interface.ifaces))
        return go_set_error(err_out, "interface list too long"), -1;

    memset(&change_interface, 0, sizeof(change_interface));
    change_interface.header.type = ALFRED_CHANGE_INTERFACE;
    change_interface.header.version = ALFRED_VERSION;
    change_interface.header.length = FIXED_TLV_LEN(change_interface);
    memcpy(change_interface.ifaces, ifaces, length);

    if (go_unix_sock_open_client(client->globals, err_out))
        return -1;

    if (go_write_exact(client->globals->unix_sock, (unsigned char *)&change_interface,
                       sizeof(change_interface)) < (ssize_t)sizeof(change_interface)) {
        go_set_error(err_out, "failed to send interface change: %s", strerror(errno));
        goto out;
    }

    result = 0;

out:
    go_unix_sock_close(client->globals);
    return result;
}

int go_alfred_client_change_bat_iface(go_alfred_client *client, const char *iface, char **err_out)
{
    struct alfred_change_bat_iface_v0 change_iface;
    size_t length;
    int result = -1;

    if (err_out)
        *err_out = NULL;

    if (!client || !client->globals)
        return go_set_error(err_out, "invalid client"), -1;

    if (!iface || !iface[0])
        return go_set_error(err_out, "interface name must not be empty"), -1;

    length = strlen(iface);
    if (length >= sizeof(change_iface.bat_iface))
        return go_set_error(err_out, "interface name too long"), -1;

    memset(&change_iface, 0, sizeof(change_iface));
    change_iface.header.type = ALFRED_CHANGE_BAT_IFACE;
    change_iface.header.version = ALFRED_VERSION;
    change_iface.header.length = FIXED_TLV_LEN(change_iface);
    memcpy(change_iface.bat_iface, iface, length);

    if (go_unix_sock_open_client(client->globals, err_out))
        return -1;

    if (go_write_exact(client->globals->unix_sock, (unsigned char *)&change_iface,
                       sizeof(change_iface)) < (ssize_t)sizeof(change_iface)) {
        go_set_error(err_out, "failed to send bat iface change: %s", strerror(errno));
        goto out;
    }

    result = 0;

out:
    go_unix_sock_close(client->globals);
    return result;
}

void go_alfred_record_get_source(go_alfred_record *record, uint8_t out[6])
{
    memcpy(out, record->source, ETH_ALEN);
}

uint8_t go_alfred_record_get_version(go_alfred_record *record)
{
    return record->version;
}

uint8_t *go_alfred_record_get_data(go_alfred_record *record)
{
    return record->data;
}

size_t go_alfred_record_get_data_len(go_alfred_record *record)
{
    return record->data_len;
}

static void go_server_free_dataset(void *data)
{
    struct dataset *dataset = data;

    if (!dataset)
        return;

    free(dataset->buf);
    free(dataset);
}

static void go_server_free_transaction(void *data)
{
    struct transaction_head *head = data;
    struct transaction_packet *packet, *tmp;

    if (!head)
        return;

    list_for_each_entry_safe(packet, tmp, &head->packet_list, list) {
        free(packet->push);
        free(packet);
    }

    if (head->client_socket >= 0)
        close(head->client_socket);

    free(head);
}

static void go_alfred_server_cleanup(struct go_alfred_server *server)
{
    struct globals *globals;

    if (!server || !server->globals)
        return;

    globals = server->globals;

    netsock_close_all(globals);
    unix_sock_close(globals);
    unix_sock_events_close_all(globals);

    if (globals->check_timerfd >= 0) {
        close(globals->check_timerfd);
        globals->check_timerfd = -1;
    }

    if (globals->epollfd >= 0) {
        close(globals->epollfd);
        globals->epollfd = -1;
    }

    if (globals->data_hash) {
        hash_delete(globals->data_hash, go_server_free_dataset);
        globals->data_hash = NULL;
    }

    if (globals->transaction_hash) {
        hash_delete(globals->transaction_hash, go_server_free_transaction);
        globals->transaction_hash = NULL;
    }

    free(globals->net_iface);
    globals->net_iface = NULL;

    free(globals->mesh_iface);
    globals->mesh_iface = NULL;

    if (globals->unix_path) {
        free((void *)globals->unix_path);
        globals->unix_path = NULL;
    }

    globals->best_server = NULL;

    free(globals);
    server->globals = NULL;
}

static void *go_alfred_server_thread(void *arg)
{
    struct go_alfred_server *server = arg;
    int ret = alfred_server(server->globals);

    return (void *)(intptr_t)ret;
}

go_alfred_server *go_alfred_server_new(const char *unix_path, const char *net_iface, const char *mesh_iface, uint8_t opmode, int force, char **err_out)
{
    struct go_alfred_server *server;
    struct globals *globals;

    if (err_out)
        *err_out = NULL;

    if (opmode != OPMODE_PRIMARY && opmode != OPMODE_SECONDARY)
        return go_set_error(err_out, "invalid server mode"), NULL;

    server = calloc(1, sizeof(*server));
    if (!server)
        return go_set_error(err_out, "out of memory"), NULL;

    globals = calloc(1, sizeof(*globals));
    if (!globals) {
        free(server);
        return go_set_error(err_out, "out of memory"), NULL;
    }

    INIT_LIST_HEAD(&globals->interfaces);
    INIT_LIST_HEAD(&globals->event_listeners);

    globals->best_server = NULL;
    globals->data_hash = NULL;
    globals->transaction_hash = NULL;
    globals->clientmode = CLIENT_NONE;
    globals->clientmode_arg = 0;
    globals->clientmode_version = 0;
    globals->verbose = 0;
    globals->ipv4mode = 0;
    globals->force = force ? 1 : 0;
    globals->opmode = (enum opmode)opmode;

    globals->net_iface = strdup(net_iface ? net_iface : "none");
    if (!globals->net_iface)
        goto err;

    globals->mesh_iface = strdup(mesh_iface ? mesh_iface : "none");
    if (!globals->mesh_iface)
        goto err;

    globals->unix_path = unix_path ? strdup(unix_path) : strdup(ALFRED_SOCK_PATH_DEFAULT);
    if (!globals->unix_path)
        goto err;

    globals->update_command = NULL;
    globals->epollfd = -1;
    globals->check_timerfd = -1;
    globals->unix_sock = -1;
    globals->sync_period.tv_sec = ALFRED_INTERVAL;
    globals->sync_period.tv_nsec = 0;
    bitmap_zero(globals->changed_data_types, ALFRED_NUM_TYPES);

    server->globals = globals;
    server->running = 0;

    return server;

err:
    free(globals->net_iface);
    free(globals->mesh_iface);
    if (globals->unix_path)
        free((void *)globals->unix_path);
    free(globals);
    free(server);
    return go_set_error(err_out, "out of memory"), NULL;
}

int go_alfred_server_start(go_alfred_server *server, char **err_out)
{
    struct timespec ts;
    void *thread_ret = NULL;
    int ret;

    if (err_out)
        *err_out = NULL;

    if (!server || !server->globals)
        return go_set_error(err_out, "invalid server instance"), -1;

    if (server->running)
        return 0;

    ret = pthread_create(&server->thread, NULL, go_alfred_server_thread, server);
    if (ret != 0) {
        go_set_error(err_out, "pthread_create: %s", strerror(ret));
        return -1;
    }

    server->running = 1;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 200000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_nsec -= 1000000000L;
        ts.tv_sec += 1;
    }

    ret = pthread_timedjoin_np(server->thread, &thread_ret, &ts);
    if (ret == 0) {
        int exit_code = (int)(intptr_t)thread_ret;

        server->running = 0;
        server->thread = (pthread_t)0;
        go_alfred_server_cleanup(server);
        go_set_error(err_out, "alfred server exited with code %d", exit_code);
        return -1;
    } else if (ret != ETIMEDOUT) {
        server->running = 0;
        server->thread = (pthread_t)0;
        go_alfred_server_cleanup(server);
        go_set_error(err_out, "pthread_timedjoin_np: %s", strerror(ret));
        return -1;
    }

    return 0;
}

int go_alfred_server_stop(go_alfred_server *server, char **err_out)
{
    int ret;

    if (err_out)
        *err_out = NULL;

    if (!server)
        return 0;

    if (!server->running) {
        if (server->globals)
            go_alfred_server_cleanup(server);
        return 0;
    }

    ret = pthread_cancel(server->thread);
    if (ret != 0 && ret != ESRCH) {
        go_set_error(err_out, "pthread_cancel: %s", strerror(ret));
        return -1;
    }

    ret = pthread_join(server->thread, NULL);
    if (ret != 0 && ret != ESRCH) {
        go_set_error(err_out, "pthread_join: %s", strerror(ret));
        return -1;
    }

    server->thread = (pthread_t)0;
    server->running = 0;

    go_alfred_server_cleanup(server);

    return 0;
}

void go_alfred_server_free(go_alfred_server *server)
{
    if (!server)
        return;

    if (server->running)
        go_alfred_server_stop(server, NULL);
    else
        go_alfred_server_cleanup(server);

    free(server);
}

void go_alfred_test_set_socket(int fd)
{
    test_fd_override = fd;
}

void go_alfred_client_free_string(char *str)
{
    free(str);
}
