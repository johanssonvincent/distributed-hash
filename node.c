#include "node.h"

volatile sig_atomic_t shutdown_request = 0;

int main(int argc, const char *argv[])
{
    // Seed random number generator
    srand(time(NULL));

    // Array below declares the function for each state, must be in sync with state_codes enum in node.h
    int (*state[])(Data *data) =
        {
            q1_state,
            q2_state,
            q3_state,
            q4_state,
            q5_state,
            q6_state,
            q7_state,
            q8_state,
            q9_state,
            q10_state,
            q11_state,
            q12_state,
            q13_state,
            q14_state,
            q15_state,
            q16_state,
            q17_state,
            q18_state,
            end_state};

    // Key is current state, values are possible states to transition to,
    // depending on index of return code. (q1_t = index 0)
    int state_transitions[][18] =
        {
            [q1] = {q2, es, es, es, es, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q2] = {es, q3, es, es, es, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q3] = {es, es, q4, es, es, q7, es, es, es, es, es, es, es, es, es, es, es, es},
            [q4] = {es, es, es, es, q6, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q5] = {es, es, es, es, q6, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q6] = {es, es, es, es, q6, es, es, q9, q10, es, q12, es, es, q15, q16, q17, es, es},
            [q7] = {es, es, es, es, es, es, q8, es, es, es, es, es, es, es, es, es, es, es},
            [q8] = {es, es, es, es, q6, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q9] = {es, es, es, es, q6, es, es, q9, es, es, es, es, es, es, es, es, es, es},
            [q10] = {es, es, es, es, es, es, es, es, es, q11, es, es, es, es, es, es, es, es},
            [q11] = {es, es, es, es, es, es, es, es, es, es, es, es, es, es, es, es, q18, es},
            [q12] = {es, es, es, q5, es, es, es, es, es, es, es, q13, q14, es, es, es, es, es},
            [q13] = {es, es, es, es, q6, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q14] = {es, es, es, es, q6, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q15] = {es, es, es, es, q6, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q16] = {es, es, es, es, q6, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q17] = {es, es, es, es, q6, es, es, es, es, es, es, es, es, es, es, es, es, es},
            [q18] = {es, es, es, es, es, es, es, es, es, es, es, es, es, es, es, es, es, es},
        };

    ret_codes rc;
    int (*state_fun)(Data *data);
    state_codes curr_state = q1;

    Data *data = init_data(argc, argv);

    while (1)
    {
        state_fun = state[curr_state];
        rc = state_fun(data);
        if (curr_state == es)
        {
            break;
        }
        curr_state = state_transitions[curr_state][rc];
    }

    return 0;
}

Data *init_data(int argc, const char *argv[])
{
    if (check_startup_args(argc, argv) != 0)
    {
        exit(EXIT_FAILURE);
    }

    Data *data = safe_malloc(sizeof(Data));

    data->opt.tracker_ip = safe_calloc(16, sizeof(char));
    strcpy(data->opt.tracker_ip, argv[1]);

    data->opt.tracker_port = safe_calloc(6, sizeof(char));
    strcpy(data->opt.tracker_port, argv[2]);

    // Set predecessor and successor to -1
    data->tcp_socket_D = -1;
    data->tcp_socket_B = -1;

    data->predecessor_addr = NULL;

    for (int i = 0; i < 3; i++)
    {
        data->recv_len[i] = 0;
    }

    data->last_alive = 0;

    data->ht = ht_create(&free_value);

    return data;
}

int q1_state(Data *data)
{
    printf("--q1--\n");

    /* Initialize sockets */
    init_udp_socket(data);
    data->tcp_socket_C = init_tcp_socket(data);

    if (listen(data->tcp_socket_C, 10) == -1)
    {
        perror("listen");
        exit(errno);
    }

    printf("Node listening on UDP port %d, accepts TCP connections on %d\n", data->own_udp_port, data->own_tcp_port);

    data->tracker_addr = get_tracker_addr(data);

    /* Defining lookup PDU request */
    struct STUN_LOOKUP_PDU lookup_pdu;
    memset(&lookup_pdu, 0, sizeof(lookup_pdu));
    lookup_pdu.type = STUN_LOOKUP;

    /* Sending lookup PDU request */
    if ((data->pdu_msg_len = sendto(data->udp_socket_A, &lookup_pdu, sizeof(lookup_pdu), 0,
                                    data->tracker_addr->ai_addr, data->tracker_addr->ai_addrlen)) == -1)
    {
        perror("UDP sendto");
        exit(errno);
    }

    printf("Sending STUN_LOOKUP to tracker %s:%s\n", data->opt.tracker_ip, data->opt.tracker_port);

    return q2_t;
}

int q2_state(Data *data)
{
    printf("--q2--\n");

    /* Receiving lookup PDU response */
    unsigned char buffer[STUN_RESPONSE_PDU_SIZE];
    memset(buffer, 0, sizeof(buffer));

    if ((data->pdu_msg_len = recvfrom(data->udp_socket_A, buffer, sizeof(buffer), 0,
                                      data->tracker_addr->ai_addr, &data->tracker_addr->ai_addrlen)) == -1)
    {
        perror("UDP recvfrom");
        exit(errno);
    }

    struct STUN_RESPONSE_PDU response_pdu;
    memcpy(&response_pdu.type, buffer, sizeof(response_pdu.type));
    memcpy(&response_pdu.address, buffer + sizeof(response_pdu.type), sizeof(response_pdu.address));

    if (response_pdu.type == STUN_RESPONSE)
    {
        data->own_ip = response_pdu.address;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &data->own_ip, ip, INET_ADDRSTRLEN);
        printf("Received STUN_RESPONSE, own address is %s\n", ip);
    }

    return q3_t;
}

int q3_state(Data *data)
{
    printf("--q3--\n");

    // send NET_GET_NODE to tracker
    struct NET_GET_NODE_PDU get_node_pdu;
    memset(&get_node_pdu, 0, sizeof(get_node_pdu));
    get_node_pdu.type = NET_GET_NODE;

    if ((data->pdu_msg_len = sendto(data->udp_socket_A, &get_node_pdu, sizeof(get_node_pdu), 0,
                                    data->tracker_addr->ai_addr, data->tracker_addr->ai_addrlen)) == -1)
    {
        perror("UDP sendto");
        exit(errno);
    }

    printf("Sending NET_GET_NODE to tracker\n");

    /* Receiving PDU response */
    unsigned char buffer[NET_GET_NODE_RESPONSE_PDU_SIZE];
    memset(buffer, 0, sizeof(buffer));

    if ((data->pdu_msg_len = recvfrom(data->udp_socket_A, buffer, sizeof(buffer), 0,
                                      data->tracker_addr->ai_addr, &data->tracker_addr->ai_addrlen)) == -1)
    {
        perror("UDP recvfrom");
        exit(errno);
    }

    // Prevent compiler from adding byte padding
    struct NET_GET_NODE_RESPONSE_PDU res_pdu;
    memcpy(&res_pdu.type, buffer, sizeof(res_pdu.type));
    memcpy(&res_pdu.address, buffer + sizeof(res_pdu.type), sizeof(res_pdu.address));
    memcpy(&res_pdu.port, buffer + sizeof(res_pdu.type) + sizeof(res_pdu.address), sizeof(res_pdu.port));

    printf("Receiving NET_GET_NODE_REPONSE\n");

    freeaddrinfo(data->tracker_addr);
    data->tracker_addr = NULL;

    if (res_pdu.address == 0 && res_pdu.port == 0)
    {
        printf("Received empty response, this is the first node\n");
        return q4_t;
    }
    else
    {
        // Save predecessor address
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        char ip4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &res_pdu.address, ip4, INET_ADDRSTRLEN);

        char port[6];
        sprintf(port, "%d", ntohs(res_pdu.port));

        int err;
        if ((err = getaddrinfo(ip4, port, &hints, &res)) != 0)
        {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
            exit(errno);
        }

        if (res != NULL)
        {
            data->predecessor_addr = res;
        }

        printf("Received non-empty response, joining network...\n");
        return q7_t;
    }
}

int q4_state(Data *data)
{
    printf("--q4--\n");
    // Init hashtable to network size
    data->hash_range_s = 0;
    data->hash_range_e = 255;
    return q6_t;
}

int q5_state(Data *data)
{
    printf("--q5--\n");

    struct NET_JOIN_PDU join_pdu;
    memset(&join_pdu, 0, sizeof(struct NET_JOIN_PDU));

    uint8_t *buf = data->last_pdu;

    memcpy(&join_pdu.type, buf, 1);
    memcpy(&join_pdu.src_address, buf + 1, 4);
    memcpy(&join_pdu.src_port, buf + 1 + 4, 2);
    memcpy(&join_pdu.max_span, buf + 1 + 4 + 2, 1);
    memcpy(&join_pdu.max_address, buf + 1 + 4 + 2 + 1, 4);
    memcpy(&join_pdu.max_port, buf + 1 + 4 + 2 + 1 + 4, 2);

    connect_successor(data, join_pdu.src_address, join_pdu.src_port);

    // Calculate new hash range for predecessor(current node) and successor
    int min = data->hash_range_s;
    int max = data->hash_range_e;

    int minp = min;
    int maxs = max;

    int maxp = ((max - min) / 2) + min;
    int mins = maxp + 1;

    data->hash_range_s = minp;
    data->hash_range_e = maxp;

    printf("New range is (%d, %d)\n", data->hash_range_s, data->hash_range_e);

    // Structure NET_JOIN_RESPONSE_PDU
    struct NET_JOIN_RESPONSE_PDU join_res;
    memset(&join_res, 0, sizeof(struct NET_JOIN_RESPONSE_PDU));

    join_res.type = NET_JOIN_RESPONSE;
    join_res.next_address = data->own_ip;
    join_res.next_port = htons(data->own_tcp_port);
    join_res.range_start = mins;
    join_res.range_end = maxs;

    uint8_t res_buf[NET_JOIN_RESPONSE_PDU_SIZE];
    memset(res_buf, 0, sizeof(res_buf));
    res_buf[0] = join_res.type;
    memcpy(res_buf + 1, &join_res.next_address, sizeof(join_res.next_address));
    memcpy(res_buf + 1 + 4, &join_res.next_port, sizeof(join_res.next_port));
    memcpy(res_buf + 1 + 4 + 2, &join_res.range_start, sizeof(join_res.range_start));
    memcpy(res_buf + 1 + 4 + 2 + 1, &join_res.range_end, sizeof(join_res.range_end));

    // Send NET_JOIN_RESPONSE
    if ((data->pdu_msg_len = send(data->tcp_socket_B, res_buf, sizeof(res_buf), 0)) == -1)
    {
        perror("TCP send");
        exit(errno);
    }

    // Transfer upper half of entry-range to successor (mins to maxs)
    int sent_entries = 0;
    for (int i = 0; i < MAX_SIZE; i++)
    {
        node_t *entry = data->ht->entries[i];

        while (entry != NULL)
        {
            if (mins <= i && i <= maxs)
            {
                printf("Value in successor's range, sending key; %s\n", entry->key);

                value_t *val = (value_t *)entry->value;

                // Structure VAL_INSERT_PDU
                struct VAL_INSERT_PDU val_pdu;
                memset(&val_pdu, 0, sizeof(struct VAL_INSERT_PDU));
                val_pdu.type = VAL_INSERT;

                uint8_t buf[BUFFER_SIZE * sizeof(uint8_t)];
                memset(buf, 0, BUFFER_SIZE * sizeof(uint8_t));

                buf[0] = VAL_INSERT;

                memcpy(val_pdu.ssn, val->ssn, SSN_LENGTH);

                uint8_t name_length = strlen((char *)val->name);
                uint8_t email_length = strlen((char *)val->email);

                val_pdu.name_length = name_length;
                val_pdu.email_length = email_length;

                memcpy(buf, &val_pdu, sizeof(val_pdu));

                buf[SSN_LENGTH + 1] = name_length;
                memcpy(&buf[SSN_LENGTH + 2], val->name, name_length);

                buf[SSN_LENGTH + 2 + name_length] = (uint8_t)email_length;
                memcpy(&buf[SSN_LENGTH + 3 + name_length], val->email, email_length);

                size_t buf_size = SSN_LENGTH + name_length + email_length + 3;

                // Send VAL_INSERT_PDU to successor
                if ((data->pdu_msg_len = send(data->tcp_socket_B, buf, buf_size, 0)) == -1)
                {
                    perror("TCP send");
                    exit(errno);
                }

                sent_entries++;
                hashtable_delete(data->ht, (char *)val->ssn);
            }

            entry = entry->next;
        }
    }

    printf("Sent %d entries\n", sent_entries);

    accept_predecessor(data);

    return q6_t;
}

int q6_state(Data *data)
{
    printf("--q6-- (%d entries stored)\n", get_num_entries(data->ht));

    signal(SIGINT, sig_handler);

    if (data->tracker_addr != NULL)
    {
        freeaddrinfo(data->tracker_addr);
        data->tracker_addr = NULL;
    }
    data->tracker_addr = get_tracker_addr(data);

    for (int i = 0; i < 3; i++)
    {
        if (data->recv_len[i] > 0)
        {
            return process_buffer(data, i);
        }
    }

    time_t curr = time(NULL);
    if ((curr - (data->last_alive)) > 10 || data->last_alive == 0)
    {
        // Send NET_ALIVE to tracker if 10 seconds has passed
        struct NET_ALIVE_PDU alive_pdu;
        memset(&alive_pdu, 0, sizeof(alive_pdu));
        alive_pdu.type = NET_ALIVE;
        if ((data->pdu_msg_len = sendto(data->udp_socket_A, &alive_pdu, sizeof(alive_pdu), 0,
                                        data->tracker_addr->ai_addr, data->tracker_addr->ai_addrlen)) == -1)
        {
            perror("UDP sendto");
            exit(errno);
        }
        printf("Sending NET_ALIVE\n");
        data->last_alive = time(NULL);
    }

    // Add the sockets to poll
    struct pollfd pfds[3];
    pfds[0].fd = data->udp_socket_A;
    pfds[0].events = POLLIN;
    int fd_count = 1;

    if (data->tcp_socket_D != -1)
    {
        pfds[fd_count].fd = data->tcp_socket_D;
        pfds[fd_count].events = POLLIN;
        fd_count++;
    }

    if (data->tcp_socket_B != -1)
    {
        pfds[fd_count].fd = data->tcp_socket_B;
        pfds[fd_count].events = POLLIN;
        fd_count++;
    }

    int num_events = poll(pfds, fd_count, 5000);

    if (shutdown_request == 1)
    {
        return q10_t;
    }

    if (num_events == -1)
    {
        perror("poll");
        return es_t;
    }

    for (int i = 0; i < fd_count; i++)
    {
        if ((pfds[i].revents & POLLIN))
        {
            if (pfds[i].fd == data->udp_socket_A)
            {
                int result = 0;
                if ((result = recvfrom(data->udp_socket_A, data->bufs[i] + data->recv_len[i], BUFFER_SIZE - data->recv_len[i], 0,
                                       data->tracker_addr->ai_addr, &data->tracker_addr->ai_addrlen)) == -1)
                {
                    perror("UDP recvfrom");
                    exit(errno);
                }

                data->recv_len[i] += result;

                return process_buffer(data, i);
            }
            else if (pfds[i].fd == data->tcp_socket_D || pfds[i].fd == data->tcp_socket_B)
            {
                int result = 0;
                if ((result = recv(pfds[i].fd, data->bufs[i] + data->recv_len[i], BUFFER_SIZE - data->recv_len[i], 0)) == -1)
                {
                    perror("TCP recv:");
                    exit(errno);
                }

                data->recv_len[i] += result;

                return process_buffer(data, i);
            }
        }
    }

    return q6_t;
}

int q7_state(Data *data)
{
    printf("--q7--\n");

    // send NET_JOIN to node in NET_GET_NODE_RESPONSE
    struct NET_JOIN_PDU join_pdu;
    memset(&join_pdu, 0, sizeof(join_pdu));
    join_pdu.type = NET_JOIN;
    join_pdu.src_address = data->own_ip;
    join_pdu.src_port = htons(data->own_tcp_port);

    struct pollfd fds[1];
    fds[0].fd = data->udp_socket_A;
    fds[0].events = POLLOUT;

    int ret = poll(fds, 1, 2000);
    if (ret == -1)
    {
        perror("poll");
        return es_t;
    }
    else if (ret == 0)
    {
        printf("Timeout occurred! No data after 2 seconds.\n");
        return es_t;
    }

    if (fds[0].revents & POLLOUT)
    {
        // Print the IP and port of the predecessor
        struct sockaddr_in *addr_in = (struct sockaddr_in *)data->predecessor_addr->ai_addr;
        char ip4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip4, INET_ADDRSTRLEN);
        printf("Predecessor UDP address is %s:%d\n", ip4, ntohs(addr_in->sin_port));

        // Using a buffer to send the PDU forcing it to be correct amount of bytes
        // sizeof(join_pdu) returns 20 bytes, while the fields in the pdu are 14 bytes.
        unsigned char buffer[NET_JOIN_PDU_SIZE];
        memset(buffer, 0, sizeof(buffer));
        buffer[0] = join_pdu.type;
        memcpy(buffer + 1, &join_pdu.src_address, sizeof(join_pdu.src_address));
        memcpy(buffer + 5, &join_pdu.src_port, sizeof(join_pdu.src_port));

        if ((data->pdu_msg_len = sendto(data->udp_socket_A, buffer, sizeof(buffer), 0,
                                        data->predecessor_addr->ai_addr, data->predecessor_addr->ai_addrlen)) == -1)
        {
            perror("UDP sendto");
            exit(errno);
        }

        printf("Sent NET_JOIN to predecessor\n");
    }

    // Accept predecessor
    accept_predecessor(data);

    return q8_t;
}

int q8_state(Data *data)
{
    printf("--q8--\n");

    // Receive NET_JOIN_RESPONSE from predecessor
    struct NET_JOIN_RESPONSE_PDU join_res;
    memset(&join_res, 0, sizeof(struct NET_JOIN_RESPONSE_PDU));

    struct pollfd fds[1];
    fds[0].fd = data->tcp_socket_D;
    fds[0].events = POLLIN;

    int ret = poll(fds, 1, 2000);
    if (ret == -1)
    {
        perror("poll");
        return es_t;
    }
    else if (ret == 0)
    {
        printf("Timeout occurred! No data after 2 seconds.\n");
        return es_t;
    }
    else
    {
        if (fds[0].revents & POLLIN)
        {

            int result = 0;
            if ((result = recv(data->tcp_socket_D, data->bufs[1], BUFFER_SIZE, 0)) == -1)
            {
                perror("TCP recv");
                exit(errno);
            }
            data->recv_len[1] += result;

            uint8_t buf[NET_JOIN_RESPONSE_PDU_SIZE];
            memset(&buf, 0, NET_JOIN_RESPONSE_PDU_SIZE);
            memcpy(buf, data->bufs[1], NET_JOIN_RESPONSE_PDU_SIZE);

            size_t pdu_len = NET_JOIN_RESPONSE_PDU_SIZE;
            memmove(data->bufs[1], data->bufs[1] + pdu_len, BUFFER_SIZE - pdu_len);
            data->recv_len[1] -= pdu_len;

            memcpy(&join_res.type, buf, 1);
            memcpy(&join_res.next_address, buf + 1, 4);
            memcpy(&join_res.next_port, buf + 1 + 4, 2);
            memcpy(&join_res.range_start, buf + 1 + 4 + 2, 1);
            memcpy(&join_res.range_end, buf + 1 + 4 + 2 + 1, 1);

            printf("Recieved NET_JOIN_RESPONSE from predecessor\n");
            printf("Range start: %d Range end: %d\n", join_res.range_start, join_res.range_end);

            data->hash_range_s = join_res.range_start;
            data->hash_range_e = join_res.range_end;

            data->successor_addr.sin_addr.s_addr = join_res.next_address;
            data->successor_addr.sin_port = ntohs(join_res.next_port);
        }
    }

    // Connect to successor
    connect_successor(data, join_res.next_address, join_res.next_port);

    return q6_t;
}

int q9_state(Data *data)
{
    printf("--q9--\n");

    size_t pdu_len = 0;

    if (data->last_pdu_type == VAL_INSERT)
    {
        printf("Received VAL_INSERT\n");
        size_t name_len = data->bufs[data->last_socket][1 + SSN_LENGTH];
        size_t email_len = data->bufs[data->last_socket][1 + SSN_LENGTH + 1 + name_len];
        pdu_len = SSN_LENGTH + name_len + email_len + 3;

        memcpy(data->last_pdu, data->bufs[data->last_socket], pdu_len);

        handle_val_insert_pdu(data);
    }
    else if (data->last_pdu_type == VAL_REMOVE)
    {
        printf("Received VAL_REMOVE\n");
        pdu_len = 1 + SSN_LENGTH;

        memcpy(data->last_pdu, data->bufs[data->last_socket], pdu_len);

        handle_val_remove_pdu(data);
    }
    else if (data->last_pdu_type == VAL_LOOKUP)
    {
        printf("Received VAL_LOOKUP\n");
        pdu_len = 1 + SSN_LENGTH + 4 + 2;

        memcpy(data->last_pdu, data->bufs[data->last_socket], pdu_len);

        handle_val_lookup_pdu(data);
    }

    memmove(data->bufs[data->last_socket], data->bufs[data->last_socket] + pdu_len, data->recv_len[data->last_socket]);
    data->recv_len[data->last_socket] -= pdu_len;

    return q6_t;
}

int q10_state(Data *data)
{
    printf("--q10--\n");
    if (data->tcp_socket_B == -1)
    {
        printf("No successor, last node in network\n");
        return es_t;
    }

    return q11_t;
}

int q11_state(Data *data)
{
    printf("--q11--\n");

    // Send net_new_range to predecessor or successor.
    struct NET_NEW_RANGE_PDU range_pdu;
    memset(&range_pdu, 0, sizeof(range_pdu));

    range_pdu.type = NET_NEW_RANGE;
    range_pdu.range_start = data->hash_range_s;
    range_pdu.range_end = data->hash_range_e;

    if (data->hash_range_s == 0)
    {
        // Send to successor
        if ((data->pdu_msg_len = send(data->tcp_socket_B, &range_pdu, NET_NEW_RANGE_PDU_SIZE, 0)) == -1)
        {
            perror("TCP send");
            exit(errno);
        }
    }
    else
    {
        if ((data->pdu_msg_len = send(data->tcp_socket_D, &range_pdu, NET_NEW_RANGE_PDU_SIZE, 0)) == -1)
        {
            perror("TCP send");
            exit(errno);
        }
    }

    printf("Sent NET_NEW_RANGE\n");

    struct pollfd fds[2];
    fds[0].fd = data->tcp_socket_B;
    fds[0].events = POLLIN;
    fds[1].fd = data->tcp_socket_D;
    fds[1].events = POLLIN;

    int ret = poll(fds, 2, 10000);
    if (ret == -1)
    {
        perror("poll");
        return es_t;
    }
    else if (ret == 0)
    {
        printf("Timeout occurred! No data after 10 seconds.\n");
        return es_t;
    }
    else
    {

        for (int i = 0; i < 2; i++)
        {
            /* Receiving lookup PDU response */
            uint8_t buf[NET_NEW_RANGE_PDU_SIZE];
            memset(buf, 0, sizeof(buf));

            if (fds[i].revents & POLLIN)
            {
                if ((data->pdu_msg_len = recv(fds[i].fd, buf, sizeof(buf), 0)) == -1)
                {
                    perror("TCP recv");
                    exit(errno);
                }
            }

            struct NET_NEW_RANGE_RESPONSE_PDU range_res;
            memcpy(&range_res.type, buf, sizeof(range_res.type));

            if (range_res.type == NET_NEW_RANGE_RESPONSE)
            {
                return q18_t;
            }
        }
    }

    return es_t;
}

int q12_state(Data *data)
{
    printf("--q12--\n");
    if (data->tcp_socket_B == -1)
    {
        // No node connected, no need to forward PDU.
        printf("Empty successor address, moving to q5\n");
        return q5_t;
    }

    struct NET_JOIN_PDU join_pdu;
    memset(&join_pdu, 0, sizeof(join_pdu));
    memcpy(&join_pdu.type, data->last_pdu, sizeof(join_pdu));
    memcpy(&join_pdu.src_address, data->last_pdu + 1, sizeof(join_pdu.src_address));
    memcpy(&join_pdu.src_port, data->last_pdu + 1 + 4, sizeof(join_pdu.src_port));
    memcpy(&join_pdu.max_span, data->last_pdu + 1 + 4 + 2, sizeof(join_pdu.max_span));
    memcpy(&join_pdu.max_address, data->last_pdu + 1 + 4 + 2 + 1, sizeof(join_pdu.max_address));
    memcpy(&join_pdu.max_port, data->last_pdu + 1 + 4 + 2 + 1 + 4, sizeof(join_pdu.max_port));

    if (data->own_ip == join_pdu.max_address &&
        data->own_tcp_port == ntohs(join_pdu.max_port))
    {
        printf("I'm the node with the max span: %d\n", join_pdu.max_span);
        return q13_t;
    }

    return q14_t;
}

int q13_state(Data *data)
{
    printf("--q13--\n");

    // Previous successor saved.
    struct sockaddr_in prev_successor = data->successor_addr;

    // Send NET_CLOSE_CONNECTION to successor
    struct NET_CLOSE_CONNECTION_PDU net_close;
    memset(&net_close, 0, sizeof(net_close));
    net_close.type = NET_CLOSE_CONNECTION;

    if ((data->pdu_msg_len = send(data->tcp_socket_B, &net_close, NET_CLOSE_CONNECTION_PDU_SIZE, 0)) == -1)
    {
        perror("TCP send");
        exit(errno);
    }

    close(data->tcp_socket_B);
    data->tcp_socket_B = -1;

    // Connect to prospect
    struct NET_JOIN_PDU join_pdu;
    memset(&join_pdu, 0, sizeof(join_pdu));
    memcpy(&join_pdu.type, data->last_pdu, sizeof(join_pdu));
    memcpy(&join_pdu.src_address, data->last_pdu + 1, sizeof(join_pdu.src_address));
    memcpy(&join_pdu.src_port, data->last_pdu + 1 + 4, sizeof(join_pdu.src_port));
    memcpy(&join_pdu.max_span, data->last_pdu + 1 + 4 + 2, sizeof(join_pdu.max_span));
    memcpy(&join_pdu.max_address, data->last_pdu + 1 + 4 + 2 + 1, sizeof(join_pdu.max_address));
    memcpy(&join_pdu.max_port, data->last_pdu + 1 + 4 + 2 + 1 + 4, sizeof(join_pdu.max_port));

    data->successor_addr.sin_addr.s_addr = join_pdu.src_address;
    data->successor_addr.sin_port = ntohs(join_pdu.src_port);

    connect_successor(data, join_pdu.src_address, join_pdu.src_port);

    // Calculate new hash range for predecessor(current node) and successor
    int min = data->hash_range_s;
    int max = data->hash_range_e;

    int minp = min;
    int maxs = max;

    int maxp = ((max - min) / 2) + min;
    int mins = maxp + 1;

    data->hash_range_s = minp;
    data->hash_range_e = maxp;

    printf("New range is (%d, %d)\n", data->hash_range_s, data->hash_range_e);

    // Structure NET_JOIN_RESPONSE_PDU
    struct NET_JOIN_RESPONSE_PDU join_res;
    memset(&join_res, 0, sizeof(struct NET_JOIN_RESPONSE_PDU));

    join_res.type = NET_JOIN_RESPONSE;
    join_res.next_address = prev_successor.sin_addr.s_addr;
    join_res.next_port = htons(prev_successor.sin_port);
    join_res.range_start = mins;
    join_res.range_end = maxs;

    uint8_t res_buf[NET_JOIN_RESPONSE_PDU_SIZE];
    memset(res_buf, 0, sizeof(res_buf));
    res_buf[0] = join_res.type;
    memcpy(res_buf + 1, &join_res.next_address, sizeof(join_res.next_address));
    memcpy(res_buf + 1 + 4, &join_res.next_port, sizeof(join_res.next_port));
    memcpy(res_buf + 1 + 4 + 2, &join_res.range_start, sizeof(join_res.range_start));
    memcpy(res_buf + 1 + 4 + 2 + 1, &join_res.range_end, sizeof(join_res.range_end));

    // Send NET_JOIN_RESPONSE
    if ((data->pdu_msg_len = send(data->tcp_socket_B, res_buf, sizeof(res_buf), 0)) == -1)
    {
        perror("TCP send");
        exit(errno);
    }

    // Transfer upper half of entry-range to successor (mins to maxs)
    for (int i = 0; i < MAX_SIZE; i++)
    {
        node_t *entry = data->ht->entries[i];

        while (entry != NULL)
        {
            if (mins <= i && i <= maxs)
            {
                printf("Value in successor's range, sending key %s\n", entry->key);

                value_t *val = (value_t *)entry->value;

                // Structure VAL_INSERT_PDU
                struct VAL_INSERT_PDU val_pdu;
                memset(&val_pdu, 0, sizeof(struct VAL_INSERT_PDU));
                val_pdu.type = VAL_INSERT;

                uint8_t buf[BUFFER_SIZE * sizeof(uint8_t)];
                memset(buf, 0, BUFFER_SIZE * sizeof(uint8_t));

                buf[0] = VAL_INSERT;

                memcpy(val_pdu.ssn, val->ssn, SSN_LENGTH);

                uint8_t name_length = strlen((char *)val->name);
                uint8_t email_length = strlen((char *)val->email);

                val_pdu.name_length = name_length;
                val_pdu.email_length = email_length;

                memcpy(buf, &val_pdu, sizeof(val_pdu));

                buf[SSN_LENGTH + 1] = name_length;
                memcpy(&buf[SSN_LENGTH + 2], val->name, name_length);

                buf[SSN_LENGTH + 2 + name_length] = (uint8_t)email_length;
                memcpy(&buf[SSN_LENGTH + 3 + name_length], val->email, email_length);

                size_t buf_size = SSN_LENGTH + name_length + email_length + 3;

                // Send VAL_INSERT_PDU to successor
                if ((data->pdu_msg_len = send(data->tcp_socket_B, buf, buf_size, 0)) == -1)
                {
                    perror("TCP send");
                    exit(errno);
                }

                hashtable_delete(data->ht, (char *)val->ssn);
            }

            entry = entry->next;
        }
    }

    return q6_t;
}

int q14_state(Data *data)
{
    printf("--q14--\n");

    struct NET_JOIN_PDU join_pdu;
    memset(&join_pdu, 0, sizeof(join_pdu));
    memcpy(&join_pdu.type, data->last_pdu, sizeof(join_pdu.type));
    memcpy(&join_pdu.src_address, data->last_pdu + 1, sizeof(join_pdu.src_address));
    memcpy(&join_pdu.src_port, data->last_pdu + 1 + 4, sizeof(join_pdu.src_port));
    memcpy(&join_pdu.max_span, data->last_pdu + 1 + 4 + 2, sizeof(join_pdu.max_span));
    memcpy(&join_pdu.max_address, data->last_pdu + 1 + 4 + 2 + 1, sizeof(join_pdu.max_address));
    memcpy(&join_pdu.max_port, data->last_pdu + 1 + 4 + 2 + 1 + 4, sizeof(join_pdu.max_port));

    if ((data->hash_range_e - data->hash_range_s) > join_pdu.max_span)
    {
        printf("Updating max fields\n");
        join_pdu.max_span = data->hash_range_e - data->hash_range_s;
        join_pdu.max_address = data->own_ip;
        join_pdu.max_port = htons(data->own_tcp_port);
    }

    uint8_t buf[NET_JOIN_PDU_SIZE];
    memcpy(buf, &join_pdu.type, sizeof(join_pdu.type));
    memcpy(buf + 1, &join_pdu.src_address, sizeof(join_pdu.src_address));
    memcpy(buf + 1 + 4, &join_pdu.src_port, sizeof(join_pdu.src_port));
    memcpy(buf + 1 + 4 + 2, &join_pdu.max_span, sizeof(join_pdu.max_span));
    memcpy(buf + 1 + 4 + 2 + 1, &join_pdu.max_address, sizeof(join_pdu.max_address));
    memcpy(buf + 1 + 4 + 2 + 1 + 4, &join_pdu.max_port, sizeof(join_pdu.max_port));

    printf("Forwarding NET_JOIN to successor\n");
    if ((data->pdu_msg_len = send(data->tcp_socket_B, buf, sizeof(buf), 0)) == -1)
    {
        perror("TCP send");
        exit(errno);
    }

    return q6_t;
}

int q15_state(Data *data)
{
    printf("--q15--\n");
    printf("Current hash range is: (%d, %d)\n", data->hash_range_s, data->hash_range_e);

    int new_s = data->last_pdu[1];
    int new_e = data->last_pdu[2];

    struct NET_NEW_RANGE_RESPONSE_PDU range_res;
    memset(&range_res, 0, sizeof(range_res));
    range_res.type = NET_NEW_RANGE_RESPONSE;

    if (data->hash_range_e != 255 && new_s == (data->hash_range_e + 1))
    {
        printf("Sending NEW_RANGE_RESPONSE to successor\n");
        if ((data->pdu_msg_len = send(data->tcp_socket_B, &range_res, sizeof(range_res), 0)) == -1)
        {
            perror("TCP send");
            exit(errno);
        }
        data->hash_range_e = new_e;
    }
    else
    {
        printf("Sending NEW_RANGE_RESPONSE to predecessor\n");
        if ((data->pdu_msg_len = send(data->tcp_socket_D, &range_res, sizeof(range_res), 0)) == -1)
        {
            perror("TCP send");
            exit(errno);
        }
        data->hash_range_s = new_s;
    }

    printf("New hash range is: (%d, %d)\n", data->hash_range_s, data->hash_range_e);

    return q6_t;
}

int q16_state(Data *data)
{
    printf("--q16--\n");

    struct NET_LEAVING_PDU leave_pdu;
    memset(&leave_pdu, 0, sizeof(leave_pdu));

    memcpy(&leave_pdu.type, data->last_pdu, sizeof(leave_pdu.type));
    memcpy(&leave_pdu.new_address, data->last_pdu + 1, sizeof(leave_pdu.new_address));
    memcpy(&leave_pdu.new_port, data->last_pdu + 1 + 4, sizeof(leave_pdu.new_port));

    if (leave_pdu.new_address == data->own_ip &&
        ntohs(leave_pdu.new_port) == data->own_tcp_port)
    {
        printf("I am the last node\n");
        if (data->tcp_socket_D != -1)
        {
            close(data->tcp_socket_D);
        }
        if (data->tcp_socket_B != -1)
        {
            close(data->tcp_socket_B);
        }
        data->tcp_socket_D = -1;
        data->tcp_socket_B = -1;
    }
    else
    {
        printf("I am NOT the last node, connecting to successor\n");
        close(data->tcp_socket_B);
        data->tcp_socket_B = -1;

        // Connect to new successor leave_pdu.new_address.
        connect_successor(data, leave_pdu.new_address, leave_pdu.new_port);
    }

    return q6_t;
}

int q17_state(Data *data)
{
    printf("--q17--\n");
    // Disconnect from predecessor
    printf("Disconnecting from predecessor...\n");
    close(data->tcp_socket_D);
    data->tcp_socket_D = -1;

    // If this node isn't the last node, accept new predecessor
    if ((data->hash_range_s == 0) && (data->hash_range_e == 255))
    {
        printf("I am the last node\n");
    }
    else
    {
        printf("Accepting new predecessor\n");
        accept_predecessor(data);
    }

    return q6_t;
}

int q18_state(Data *data)
{
    printf("--q18--\n");

    // Transfer entries to predecessor or successor
    int fd = -1;

    if (data->hash_range_s == 0)
    {
        // Send to successor
        fd = data->tcp_socket_B;
    }
    else
    {
        fd = data->tcp_socket_B;
    }

    // Transfer all entries
    for (int i = 0; i < MAX_SIZE; i++)
    {
        node_t *entry = data->ht->entries[i];

        while (entry != NULL)
        {

            value_t *val = (value_t *)entry->value;

            // Structure VAL_INSERT_PDU
            struct VAL_INSERT_PDU val_pdu;
            memset(&val_pdu, 0, sizeof(struct VAL_INSERT_PDU));
            val_pdu.type = VAL_INSERT;

            uint8_t buf[BUFFER_SIZE * sizeof(uint8_t)];
            memset(buf, 0, BUFFER_SIZE * sizeof(uint8_t));

            buf[0] = VAL_INSERT;

            memcpy(val_pdu.ssn, val->ssn, SSN_LENGTH);

            uint8_t name_length = strlen((char *)val->name);
            uint8_t email_length = strlen((char *)val->email);

            val_pdu.name_length = name_length;
            val_pdu.email_length = email_length;

            memcpy(buf, &val_pdu, sizeof(val_pdu));

            buf[SSN_LENGTH + 1] = name_length;
            memcpy(&buf[SSN_LENGTH + 2], val->name, name_length);

            buf[SSN_LENGTH + 2 + name_length] = (uint8_t)email_length;
            memcpy(&buf[SSN_LENGTH + 3 + name_length], val->email, email_length);

            size_t buf_size = SSN_LENGTH + name_length + email_length + 3;

            printf("Sending entry with SSN: %s\n", val_pdu.ssn);

            // Send VAL_INSERT_PDU to successor or predecessor
            if ((data->pdu_msg_len = send(fd, buf, buf_size, 0)) == -1)
            {
                perror("TCP send");
                exit(errno);
            }

            entry = entry->next;

            hashtable_delete(data->ht, (char *)val->ssn);

        }
    }

    // Send NET_CLOSE_CONNECTION to successor
    struct NET_CLOSE_CONNECTION_PDU net_close;
    memset(&net_close, 0, sizeof(net_close));
    net_close.type = NET_CLOSE_CONNECTION;

    if ((data->pdu_msg_len = send(data->tcp_socket_B, &net_close, sizeof(net_close), 0)) == -1)
    {
        perror("TCP send");
        exit(errno);
    }

    printf("Sent NET_CLOSE\n");

    close(data->tcp_socket_B);
    data->tcp_socket_B = -1;

    // Send NET_LEAVING to predecessor
    struct NET_LEAVING_PDU leave_pdu;
    memset(&leave_pdu, 0, sizeof(leave_pdu));

    leave_pdu.type = NET_LEAVING;
    leave_pdu.new_address = data->successor_addr.sin_addr.s_addr;
    leave_pdu.new_port = htons(data->successor_addr.sin_port);

    // sizeof(leave_pdu) returns 12 bytes, while the fields in the pdu are 7 bytes.
    uint8_t res_buf[NET_LEAVING_PDU_SIZE];
    memset(res_buf, 0, sizeof(res_buf));

    res_buf[0] = leave_pdu.type;
    memcpy(res_buf + 1, &leave_pdu.new_address, sizeof(uint32_t));
    memcpy(res_buf + 1 + 4, &leave_pdu.new_port, sizeof(uint16_t));

    if ((data->pdu_msg_len = send(data->tcp_socket_D, &res_buf, sizeof(res_buf), 0)) == -1)
    {
        perror("TCP send");
        exit(errno);
    }

    printf("Sent NET_LEAVING\n");

    close(data->tcp_socket_D);
    data->tcp_socket_D = -1;

    return es_t;
}

int end_state(Data *data)
{
    printf("--end state--\n");
    if (data->tracker_addr != NULL)
    {
        freeaddrinfo(data->tracker_addr);
    }
    if (data->predecessor_addr != NULL)
    {
        freeaddrinfo(data->predecessor_addr);
    }
    free(data->opt.tracker_ip);
    free(data->opt.tracker_port);
    ht_destroy(data->ht);
    free(data);
    printf("Shutting down...\n");
    return es_t;
}

int check_startup_args(int argc, const char *argv[])
{
    if (argc != 3)
    {
        printf("USAGE:\n%s <tracker address> <tracker port> \n", argv[0]);
        return -1;
    }
    return 0;
}

struct addrinfo *get_tracker_addr(Data *data)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int err;
    if ((err = getaddrinfo(data->opt.tracker_ip, data->opt.tracker_port, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(errno);
    }

    if (res == NULL)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(errno);
    }
    return res;
}

struct addrinfo *get_client_addr(uint32_t c_addr, uint16_t c_port)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct sockaddr_in c_sockaddr_in;
    c_sockaddr_in.sin_addr.s_addr = c_addr;
    c_sockaddr_in.sin_port = c_port;

    char ip4[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(c_sockaddr_in.sin_addr), ip4, INET_ADDRSTRLEN);

    char port[6];
    sprintf(port, "%d", ntohs(c_sockaddr_in.sin_port));

    int err;
    if ((err = getaddrinfo(ip4, port, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(errno);
    }

    if (res == NULL)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(errno);
    }

    return res;
}

void connect_successor(Data *data, uint32_t n_addr, uint16_t n_port)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct sockaddr_in n_sockaddr_in;
    n_sockaddr_in.sin_addr.s_addr = n_addr;
    n_sockaddr_in.sin_port = n_port;

    char ip4[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(n_sockaddr_in.sin_addr), ip4, INET_ADDRSTRLEN);

    char port[6];
    sprintf(port, "%d", ntohs(n_sockaddr_in.sin_port));

    printf("Connecting to successor %s:%s\n", ip4, port);

    int err;
    if ((err = getaddrinfo(ip4, port, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(errno);
    }

    if (res == NULL)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(errno);
    }

    if ((data->tcp_socket_B = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
    {
        perror("Successor socket: ");
    }

    if (connect(data->tcp_socket_B, res->ai_addr, res->ai_addrlen) == -1)
    {
        close(data->tcp_socket_B);
        perror("Successor connect: ");
    }

    fcntl(data->tcp_socket_B, F_SETFL, O_NONBLOCK);
    freeaddrinfo(res);

    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);

    if (getsockname(data->tcp_socket_B, (struct sockaddr *)&local_addr, &addr_len) == -1)
    {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    printf("Successfully connected to successor. Using port: %d\n",  ntohs(local_addr.sin_port));

    data->successor_addr.sin_addr.s_addr = n_addr;
    data->successor_addr.sin_port = ntohs(n_port);
}

void accept_predecessor(Data *data)
{
    struct pollfd fds[1];
    fds[0].fd = data->tcp_socket_C;
    fds[0].events = POLLIN;

    int ret = poll(fds, 1, 2000);
    if (ret == -1)
    {
        perror("poll");
    }
    else if (ret == 0)
    {
        printf("Timeout occurred! No data after 2 seconds.\n");
    }
    else
    {
        if (fds[0].revents & POLLIN)
        {
            struct sockaddr_in their_addr;
            socklen_t addr_size = sizeof(their_addr);
            if ((data->tcp_socket_D = accept(fds[0].fd, (struct sockaddr *)&their_addr, &addr_size)) == -1)
            {
                perror("accept");
                exit(errno);
            }
        }

        fcntl(data->tcp_socket_D, F_SETFL, O_NONBLOCK);

        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);

        if (getsockname(data->tcp_socket_D, (struct sockaddr *)&local_addr, &addr_len) == -1)
        {
            perror("getsockname");
            exit(EXIT_FAILURE);
        }

        printf("Successfully accepted predecessor. Using port: %d\n",  ntohs(local_addr.sin_port));
    }
}

void init_udp_socket(Data *data)
{
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    data->own_udp_port = generate_port();
    char port_s[6];
    sprintf(port_s, "%d", data->own_udp_port);

    int err;
    if ((err = getaddrinfo(NULL, port_s, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(errno);
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        if ((data->udp_socket_A = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("udp socket");
            continue;
        }

        if (bind(data->udp_socket_A, p->ai_addr, p->ai_addrlen) == -1)
        {
            perror("udp bind");
            continue;
        }
    }

    freeaddrinfo(res);
}

int init_tcp_socket(Data *data)
{
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    data->own_tcp_port = generate_port();
    char port_s[6];
    sprintf(port_s, "%d", data->own_tcp_port);

    int err;
    if ((err = getaddrinfo(NULL, port_s, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(errno);
    }

    int listenfd;
    for (p = res; p != NULL; p = p->ai_next)
    {
        if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("tcp socket");
            continue;
        }

        int yes = 1;
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(errno);
        }

        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(listenfd);
            perror("tcp bind");
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL)
    {
        perror("tcp bind");
        exit(errno);
    }

    return listenfd;
}

int process_buffer(Data *data, int socket)
{
    uint8_t type = data->bufs[socket][0];
    data->last_pdu_type = type;

    if (type == NET_JOIN)
    {
        printf("Received NET_JOIN PDU\n");
        size_t pdu_len = NET_JOIN_PDU_SIZE;
        memcpy(data->last_pdu, data->bufs[socket], pdu_len);
        memmove(data->bufs[socket], data->bufs[socket] + pdu_len, BUFFER_SIZE - pdu_len);

        data->recv_len[socket] -= pdu_len;

        return q12_t;
    }
    else if (data->last_pdu_type == NET_NEW_RANGE)
    {
        printf("Received NET_NEW_RANGE\n");
        size_t pdu_len = NET_NEW_RANGE_PDU_SIZE;
        memcpy(data->last_pdu, data->bufs[socket], pdu_len);
        memmove(data->bufs[socket], data->bufs[socket] + pdu_len, data->recv_len[socket]);

        data->recv_len[socket] -= pdu_len;

        return q15_t;
    }
    else if (data->last_pdu_type == NET_LEAVING)
    {
        printf("Received NET_LEAVING\n");
        size_t pdu_len = NET_LEAVING_PDU_SIZE;
        memcpy(data->last_pdu, data->bufs[socket], pdu_len);
        memmove(data->bufs[socket], data->bufs[socket] + pdu_len, data->recv_len[socket]);

        data->recv_len[socket] -= pdu_len;

        return q16_t;
    }
    else if (data->last_pdu_type == NET_CLOSE_CONNECTION)
    {
        printf("Received NET_CLOSE_CONNECTION\n");
        size_t pdu_len = NET_CLOSE_CONNECTION_PDU_SIZE;
        memcpy(data->last_pdu, data->bufs[socket], pdu_len);
        memmove(data->bufs[socket], data->bufs[socket] + pdu_len, data->recv_len[socket]);

        data->recv_len[socket] -= pdu_len;

        return q17_t;
    }
    else if (data->last_pdu_type >= 100 && data->last_pdu_type <= 103)
    {
        memcpy(data->last_pdu, data->bufs[socket], BUFFER_SIZE);
        data->last_socket = socket;
        return q9_t;
    }
    else
    {
        printf("Received Invalid PDU!\n");
        return q6_t;
    }
}

int generate_port()
{
    return rand() % (MAX_PORT - MIN_PORT + 1) + MIN_PORT;
}

void handle_val_insert_pdu(Data *data)
{
    struct VAL_INSERT_PDU val_ins;
    memset(&val_ins, 0, sizeof(val_ins));

    uint8_t *buf = data->last_pdu;
    int i = 0;

    val_ins.type = buf[i++];

    char ssn[SSN_LENGTH];
    for (int j = 0; j < SSN_LENGTH; j++)
    {
        ssn[j] = buf[i++];
    }

    memcpy(val_ins.ssn, ssn, SSN_LENGTH);

    val_ins.name_length = buf[i++];

    char name[val_ins.name_length];
    for (int j = 0; j < val_ins.name_length; j++)
    {
        name[j] = buf[i++];
    }

    val_ins.name = safe_malloc(val_ins.name_length * sizeof(uint8_t *));
    memcpy(val_ins.name, name, val_ins.name_length);

    val_ins.email_length = buf[i++];

    char email[val_ins.email_length];
    for (int j = 0; j < val_ins.email_length; j++)
    {
        email[j] = buf[i++];
    }

    val_ins.email = safe_malloc(val_ins.email_length * sizeof(uint8_t *));
    memcpy(val_ins.email, email, val_ins.email_length);

    hash_t index = hash_ssn((char *)val_ins.ssn);

    if (index >= data->hash_range_s && index <= data->hash_range_e)
    {
        printf("Inserting index:key: %d:%.*s\n", index, 12, ssn);
        hashtable_insert(data->ht, val_ins);
    }
    else
    {
        // Send val insert to successor since it's outside this node's range.
        printf("Outside this node's range, forwarding...\n");

        size_t buf_size = SSN_LENGTH + val_ins.name_length + val_ins.email_length + 3;
        if ((data->pdu_msg_len = send(data->tcp_socket_B, buf, buf_size, 0)) == -1)
        {
            perror("TCP send");
            exit(errno);
        }
    }

    free(val_ins.name);
    free(val_ins.email);
}

void handle_val_remove_pdu(Data *data)
{
    struct VAL_REMOVE_PDU val_rem;
    memset(&val_rem, 0, sizeof(val_rem));

    uint8_t *buf = data->last_pdu;

    int i = 0;

    val_rem.type = buf[i++];

    char ssn[SSN_LENGTH];
    for (int j = 0; j < SSN_LENGTH; j++)
    {
        ssn[j] = buf[i++];
    }

    memcpy(val_rem.ssn, ssn, SSN_LENGTH);

    hash_t index = hash_ssn((char *)val_rem.ssn);
    if (index >= data->hash_range_s && index <= data->hash_range_e)
    {
        hashtable_delete(data->ht, (char *)val_rem.ssn);
    }
    else
    {
        // Send val remove to successor since it's outside this node's range.
        printf("Outside this node's range, forwarding...\n");

        if ((data->pdu_msg_len = send(data->tcp_socket_B, buf, VAL_REMOVE_PDU_SIZE, 0)) == -1)
        {
            perror("TCP send");
            exit(errno);
        }
    }
}

void handle_val_lookup_pdu(Data *data)
{
    struct VAL_LOOKUP_PDU val_lok;
    memset(&val_lok, 0, sizeof(val_lok));

    uint8_t *buf = data->last_pdu;

    int i = 0;

    val_lok.type = buf[i++];

    char ssn[SSN_LENGTH];
    for (int j = 0; j < SSN_LENGTH; j++)
    {
        ssn[j] = buf[i++];
    }

    memcpy(val_lok.ssn, ssn, SSN_LENGTH);

    char sender_address[sizeof(uint32_t)];
    for (int j = 0; j < (int)sizeof(uint32_t); j++)
    {
        sender_address[j] = buf[i++];
    }

    memcpy(&(val_lok.sender_address), sender_address, sizeof(uint32_t));

    char sender_port[sizeof(uint16_t)];
    for (int j = 0; j < (int)sizeof(uint16_t); j++)
    {
        sender_port[j] = buf[i++];
    }

    memcpy(&(val_lok.sender_port), sender_port, sizeof(uint16_t));

    hash_t index = hash_ssn((char *)val_lok.ssn);
    if (index >= data->hash_range_s && index <= data->hash_range_e)
    {
        value_t *lookup = hashtable_lookup(data->ht, (char *)val_lok.ssn);
        send_val_lookup_response(data, val_lok, lookup);
    }
    else
    {
        // Send val lookup to successor since it's outside this node's range.
        printf("Outside this node's range, forwarding...\n");

        if ((data->pdu_msg_len = send(data->tcp_socket_B, buf, VAL_LOOKUP_PDU_SIZE, 0)) == -1)
        {
            perror("TCP send");
            exit(errno);
        }
    }
}

void send_val_lookup_response(Data *data, struct VAL_LOOKUP_PDU val_lok, value_t *lookup)
{
    struct addrinfo *c_addr = get_client_addr(val_lok.sender_address, val_lok.sender_port);

    struct VAL_LOOKUP_RESPONSE_PDU val_res;
    memset(&val_res, 0, sizeof(val_res));
    val_res.type = VAL_LOOKUP_RESPONSE;

    uint8_t buf[BUFFER_SIZE * sizeof(uint8_t)];
    memset(buf, 0, BUFFER_SIZE * sizeof(uint8_t));

    buf[0] = VAL_LOOKUP_RESPONSE;
    memcpy(buf + 1, "000000000000", SSN_LENGTH);

    size_t buf_size = 1 + SSN_LENGTH + 2;

    if (lookup != NULL)
    {
        memcpy(val_res.ssn, val_lok.ssn, SSN_LENGTH);

        uint8_t name_length = strlen((char *)lookup->name);
        uint8_t email_length = strlen((char *)lookup->email);

        val_res.name_length = name_length;
        val_res.email_length = email_length;

        memcpy(buf, &val_res, sizeof(val_res));

        buf[SSN_LENGTH + 1] = name_length;
        memcpy(&buf[SSN_LENGTH + 2], lookup->name, name_length);

        buf[SSN_LENGTH + 2 + name_length] = (uint8_t)email_length;
        memcpy(&buf[SSN_LENGTH + 3 + name_length], lookup->email, email_length);

        buf_size = SSN_LENGTH + name_length + email_length + 3;
    }

    if ((data->pdu_msg_len = sendto(data->udp_socket_A, buf, buf_size, 0,
                                    c_addr->ai_addr, c_addr->ai_addrlen)) == -1)
    {
        perror("UDP sendto");
        exit(errno);
    }

    freeaddrinfo(c_addr);

    printf("Sending VAL_LOOKUP_RESPONSE\n");
}

void hashtable_insert(struct ht *ht, struct VAL_INSERT_PDU val_ins)
{
    uint8_t key[SSN_LENGTH];
    memcpy(key, val_ins.ssn, SSN_LENGTH);

    value_t *val = safe_calloc(1, sizeof(value_t));

    memcpy(val->ssn, val_ins.ssn, SSN_LENGTH);

    val->name = safe_calloc(val_ins.name_length + 1, sizeof(uint8_t));
    memcpy(val->name, val_ins.name, val_ins.name_length);

    val->email = safe_calloc(val_ins.email_length + 1, sizeof(uint8_t));
    memcpy(val->email, val_ins.email, val_ins.email_length);

    ht = ht_insert(ht, (char *)key, (void *)val);
}

void hashtable_delete(struct ht *ht, char *ssn)
{
    ht = ht_remove(ht, ssn);
}

value_t *hashtable_lookup(struct ht *ht, char *ssn)
{
    value_t *lookup = (value_t *)ht_lookup(ht, ssn);
    return lookup;
}

void sig_handler(int sig)
{
    if (sig == SIGINT)
    {
        shutdown_request = 1;
    }
}

void free_value(value_t *value)
{
    free(value->name);
    free(value->email);
    free(value);
}

void *safe_malloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL)
    {
        perror("malloc");
        exit(errno);
    }
    return ptr;
}

void *safe_calloc(int amount, size_t size)
{
    void *ptr = calloc(amount, size);
    if (ptr == NULL)
    {
        perror("calloc");
        exit(errno);
    }
    return ptr;
}

void *safe_realloc(void *ptr, size_t size)
{
    void *tmp = realloc(ptr, size);
    if (tmp == NULL)
    {
        perror("calloc");
        exit(errno);
    }
    return tmp;
}
