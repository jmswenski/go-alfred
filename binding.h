#ifndef GO_ALFRED_BINDING_H
#define GO_ALFRED_BINDING_H

#include <stddef.h>
#include <stdint.h>

typedef struct go_alfred_client go_alfred_client;
typedef struct go_alfred_server go_alfred_server;

typedef struct go_alfred_record {
    uint8_t source[6];
    uint8_t version;
    uint8_t *data;
    size_t data_len;
} go_alfred_record;

#ifdef __cplusplus
extern "C" {
#endif

go_alfred_client *go_alfred_client_new(const char *unix_path, int verbose, int ipv4_mode);
void go_alfred_client_free(go_alfred_client *client);
int go_alfred_client_request(go_alfred_client *client, uint8_t data_type, go_alfred_record **records, size_t *count, char **err_out);
void go_alfred_client_free_records(go_alfred_record *records, size_t count);
int go_alfred_client_set(go_alfred_client *client, uint8_t data_type, uint16_t version, const uint8_t *payload, size_t payload_len, char **err_out);
int go_alfred_client_modeswitch(go_alfred_client *client, uint8_t mode, char **err_out);
int go_alfred_client_change_interface(go_alfred_client *client, const char *ifaces, char **err_out);
int go_alfred_client_change_bat_iface(go_alfred_client *client, const char *iface, char **err_out);
go_alfred_server *go_alfred_server_new(const char *unix_path, const char *net_iface, const char *mesh_iface, uint8_t opmode, int force, char **err_out);
int go_alfred_server_start(go_alfred_server *server, char **err_out);
int go_alfred_server_stop(go_alfred_server *server, char **err_out);
void go_alfred_server_free(go_alfred_server *server);
void go_alfred_test_set_socket(int fd);
void go_alfred_record_get_source(go_alfred_record *record, uint8_t out[6]);
uint8_t go_alfred_record_get_version(go_alfred_record *record);
uint8_t *go_alfred_record_get_data(go_alfred_record *record);
size_t go_alfred_record_get_data_len(go_alfred_record *record);
void go_alfred_client_free_string(char *str);

#ifdef __cplusplus
}
#endif

#endif
