#ifndef NODE_H
#define NODE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>

#include "pdu.h"
#include "hashtable.h"
#include "hash.h"

#define MAX_NODES 256
#define MAX_PORT 65535
#define MIN_PORT 49152
#define BUFFER_SIZE 25600

#define STUN_RESPONSE_PDU_SIZE 5
#define VAL_REMOVE_PDU_SIZE 13
#define VAL_LOOKUP_PDU_SIZE 19
#define NET_GET_NODE_RESPONSE_PDU_SIZE 7
#define NET_JOIN_PDU_SIZE 14
#define NET_JOIN_RESPONSE_PDU_SIZE 9
#define NET_NEW_RANGE_PDU_SIZE 3
#define NET_NEW_RANGE_RESPONSE_PDU_SIZE 1
#define NET_LEAVING_PDU_SIZE 7
#define NET_CLOSE_CONNECTION_PDU_SIZE 1

typedef enum
{
    q1,
    q2,
    q3,
    q4,
    q5,
    q6,
    q7,
    q8,
    q9,
    q10,
    q11,
    q12,
    q13,
    q14,
    q15,
    q16,
    q17,
    q18,
    es
} state_codes;

typedef enum
{
    q2_t,
    q3_t,
    q4_t,
    q5_t,
    q6_t,
    q7_t,
    q8_t,
    q9_t,
    q10_t,
    q11_t,
    q12_t,
    q13_t,
    q14_t,
    q15_t,
    q16_t,
    q17_t,
    q18_t,
    es_t
} ret_codes;

typedef struct
{
    char *tracker_ip;
    char *tracker_port;
} Opt;

typedef struct value
{
    uint8_t ssn[SSN_LENGTH];
    uint8_t *name;
    uint8_t *email;
} value_t;

typedef struct
{
    Opt opt;
    uint32_t own_ip;
    int own_tcp_port;
    int own_udp_port;
    struct sockaddr_in successor_addr;
    struct addrinfo *predecessor_addr;
    struct addrinfo *tracker_addr;
    int udp_socket_A;
    int tcp_socket_B;
    int tcp_socket_B_port;
    int tcp_socket_C;
    int tcp_socket_D;
    uint16_t tcp_socket_D_port;
    uint32_t tcp_socket_D_addr;
    ssize_t pdu_msg_len;
    time_t last_alive;
    int last_socket;
    int last_pdu_type;
    uint8_t last_pdu[BUFFER_SIZE];
    uint8_t bufs[3][BUFFER_SIZE];
    int recv_len[3];
    struct ht *ht;
    int hash_range_s;
    int hash_range_e;
} Data;

/**
 * @brief Initializes the data structure with the startup arguments.
 *
 * @param argc
 * @param argv
 * @return Data*
 */
Data *init_data(int argc, const char *argv[]);

/**
 * @brief Initializes the UDP socket and listening TCP socket, then sends STUN_LOOKUP to the tracker.
 *
 * @param data
 * @return int
 */
int q1_state(Data *data);

/**
 * @brief Handles the STUN_LOOKUP_RESPONSE from the tracker.
 *
 * @param data
 * @return int
 */
int q2_state(Data *data);

/**
 * @brief Checks if network has existing nodes or not and changes state accordingly.
 *
 * @param data
 * @return int
 */
int q3_state(Data *data);

/**
 * @brief Initializes the hashtable.
 *
 * @param data
 * @return int
 */
int q4_state(Data *data);

/**
 * @brief Handles updating hashtable, successor and predecessor when a new node joins the network.
 *
 * @param data
 * @return int
 */
int q5_state(Data *data);

/**
 * @brief Default state when fully connected. Handles incoming PDUs.
 *
 * @param data
 * @return int
 */
int q6_state(Data *data);

/**
 * @brief Initiates connection to successor and accepts connection from predecessor.
 *
 * @param data
 * @return int
 */
int q7_state(Data *data);

/**
 * @brief Connects to successor and initializes the table with the values from the successor.
 *
 * @param data
 * @return int
 */
int q8_state(Data *data);

/**
 * @brief Handles VAL_INSERT, LOOKUP and REMOVE in the hashtable.
 *
 * @param data
 * @return int
 */
int q9_state(Data *data);

/**
 * @brief Transition state when shutting down the node, redirects depending on if the node is the last one or not.
 *
 * @param data
 * @return int
 */
int q10_state(Data *data);

/**
 * @brief Handles shutdown when there are still other nodes in the network.
 *
 * @param data
 * @return int
 */
int q11_state(Data *data);

/**
 * @brief Handles NET_JOIN PDU.
 *
 * @param data
 * @return int
 */
int q12_state(Data *data);

/**
 * @brief Handles NET_JOIN_RESPONSE PDU if the node has the highest range and updates the successor.
 *
 * @param data
 * @return int
 */
int q13_state(Data *data);

/**
 * @brief Forward NET_JOIN to successor.
 *
 * @param data
 * @return int
 */
int q14_state(Data *data);

/**
 * @brief Update the nodes hash range.
 *
 * @param data
 * @return int
 */
int q15_state(Data *data);

/**
 * @brief Handles successor leaving the network.
 *
 * @param data
 * @return int
 */
int q16_state(Data *data);

/**
 * @brief Handles predecessor leaving the network.
 *
 * @param data
 * @return int
 */
int q17_state(Data *data);

/**
 * @brief Handles shutdown when there are other nodes in the network.
 *
 * @param data
 * @return int
 */
int q18_state(Data *data);

/**
 * @brief Final state of the machine, frees all memory and closes all sockets.
 *
 * @param data
 * @return int
 */
int end_state(Data *data);

/**
 * @brief Verifies the startup arguments and returns 0 if they are valid, -1 otherwise.
 *
 * @param argc
 * @param argv
 * @return int
 */
int check_startup_args(int argc, const char *argv[]);

/**
 * @brief Get the tracker addr object
 *
 * @param data
 * @return struct addrinfo*
 */
struct addrinfo *get_tracker_addr(Data *data);

/**
 * @brief Get the client addr object
 *
 * @param c_addr
 * @param c_port
 * @return struct addrinfo*
 */
struct addrinfo *get_client_addr(uint32_t c_addr, uint16_t c_port);

/**
 * @brief Connects the node to its successor.
 *
 * @param data
 * @param n_addr
 * @param n_port
 */
void connect_successor(Data *data, uint32_t n_addr, uint16_t n_port);

/**
 * @brief Accepts the connection from the predecessor.
 *
 * @param data
 */
void accept_predecessor(Data *data);

/**
 * @brief Initialize the UDP socket.
 *
 * @param data
 */
void init_udp_socket(Data *data);

/**
 * @brief Initialize the TCP socket.
 *
 * @param data
 * @return int
 */
int init_tcp_socket(Data *data);

/**
 * @brief Process the buffer and change state depending on the PDU.
 *
 * @param data
 * @param socket
 * @return int
 */
int process_buffer(Data *data, int socket);

/**
 * @brief Generate a random port number.
 *
 * @return int
 */
int generate_port();

/**
 * @brief Insert the value from the PDU into the hashtable.
 *
 * @param data
 */
void handle_val_insert_pdu(Data *data);

/**
 * @brief Remove the value from the PDU from the hashtable.
 *
 * @param data
 */
void handle_val_remove_pdu(Data *data);

/**
 * @brief Lookup the value from the PDU in the hashtable.
 *
 * @param data
 */
void handle_val_lookup_pdu(Data *data);

/**
 * @brief Send the VAl_LOOKUP_RESPONSE after the lookup has been done.
 *
 * @param data
 * @param val_ins
 */
void send_val_lookup_response(Data *data, struct VAL_LOOKUP_PDU val_lok, value_t *lookup);

/**
 * @brief Inserts a value into the hashtable.
 *
 * @param ht
 * @param val_ins
 */
void hashtable_insert(struct ht *ht, struct VAL_INSERT_PDU val_ins);

/**
 * @brief Deletes a value from the hashtable.
 *
 * @param ht
 * @param ssn
 */
void hashtable_delete(struct ht *ht, char *ssn);

/**
 * @brief Looks up a value in the hashtable.
 *
 * @param ht
 * @param ssn
 * @return value_t*
 */
value_t *hashtable_lookup(struct ht *ht, char *ssn);

/**
 * @brief Signal handler for shutdown request.
 *
 * @param sig_num
 */
void sig_handler(int sig_num);

/**
 * @brief Free allocated memory for a value.
 *
 * @param value
 */
void free_value(value_t *value);

/**
 * @brief malloc with error handling.
 *
 * @param size
 * @return void*
 */
void *safe_malloc(size_t size);

/**
 * @brief calloc with error handling.
 *
 * @param amount
 * @param size
 * @return void*
 */
void *safe_calloc(int amount, size_t size);

/**
 * @brief realloc with error handling.
 *
 * @param ptr
 * @param size
 * @return void*
 */
void *safe_realloc(void *ptr, size_t size);

#endif /* NODE_H */

/**
 * @}
 */
