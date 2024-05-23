#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <cjson/cJSON.h>
#include "dns_proxy.h"

/* Black list of addresses */
char **blacklist = NULL;
int blacklist_size = 0;

/* Server address where DNS packets will be forwarded */
char upstream_server_ip[IP_STR_SIZE];
char response_msg[RESPONSE_SIZE];



int main(int argc, char **argv) {
    int server_socket, up_socket;
    struct sockaddr_in up_addr;
    socklen_t upstream_len;

    if (argc < 2) {
        printf("%s: Usage: %s <config file path>\n", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Prevent child process from becoming zombie process */
    signal(SIGCLD, SIG_IGN);
    /* Handle SIGINT in order to free allocated resources before leaving */
    signal(SIGINT, sigint_handler);

    if (load_config() < 0) {
        printf("Failed to load config from JSON\n");
        exit(EXIT_FAILURE);
    }

    /* Create, init and bind server socket */
    if ((server_socket = init_server_socket()) < 0) {
        perror("Failed to initialize server socket");
        exit(EXIT_FAILURE);
    }

    /* Create and initialize upstream server socket and address where DNS packets will be forwarded to */
    if ((up_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("failed to create server socket");
        return -1;
    }

    up_addr.sin_addr.s_addr = inet_addr(upstream_server_ip);
    up_addr.sin_family = AF_INET;
    up_addr.sin_port = htons(DNS_PORT);

    /* Process DNS packets */
    while(1) { 
        struct sockaddr_in client;
        ssize_t recv_bytes;
        socklen_t client_len;
        struct parsed_dns_request dns_req;
        char buffer[UDP_SIZE], *ip = NULL;
        
        recv_bytes = recvfrom(server_socket, buffer, UDP_SIZE, 0, (struct sockaddr *)&client, &client_len);

        /* Child to process arrived DNS packet*/
        if (fork() == 0) {
            
            
            if (parse_dns_request(buffer, &dns_req) < 0) {
                printf("Error parsing UDP datagram\n");
                exit(EXIT_FAILURE);
            }

            if (is_banned(dns_req.hostname)) {
                printf("DNS request for host name from black list detected: %s\n", dns_req.hostname);
                /* Create response to user */
                send_dns_response(server_socket, client, &dns_req);
            } else {
                ssize_t sent_bytes;

                /* Forward packet to the upstream server */
                sent_bytes = sendto(up_socket, buffer, recv_bytes, 0, (struct sockaddr *)&up_addr, sizeof(up_addr));

                /* Wait for response from upstream server and forward it to client */
                recv_bytes = recvfrom(up_socket, buffer, UDP_SIZE, 0, NULL, &upstream_len);
                sent_bytes = sendto(server_socket, buffer, recv_bytes, 0, (struct sockaddr *)&client, sizeof(client));
            }
        }
    }

    close(server_socket);
    close(up_socket);
    free_resources();
    return 0;
}

void sigint_handler(int sg) {
    free_resources();
    exit(EXIT_SUCCESS);
}

/**
 * @brief           Creates, initializes and binds server socket to accept UDP packets on 53 port
 * @return          Returns fd of created socket on success, or -1 if any error. 
*/
int init_server_socket() {
    int server_socket, opt;
    struct sockaddr_in server_addr;
    socklen_t server_len;

    if ((server_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("failed to create server socket");
        return -1;
    }

    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);

    server_len = sizeof(server_addr);
    if (bind(server_socket, (struct sockaddr*)&server_addr, server_len) < 0) {
        perror("Failed to bind server socket");
        return -1;
    }
    return server_socket;
}

/**
 * @brief           Loads JSON configuration file and parses it's fields
 * @return          Returns 0 on success, or -1 if any error.
*/
int load_config() {
    char *json_string = NULL;
    FILE *json_file = NULL;
    cJSON *config_json = NULL, *blacklist_json = NULL, *address_json = NULL, 
            *upstream_server_json = NULL, *response_msg_json = NULL;
    long size;
    int index, return_code = 0;
    size_t str_len = 0;
    
    json_file = fopen("dns_config.json", "rb");
    if (json_file == NULL) {
        perror("Failed to open config file");
        return_code -1;
        goto out;
    }

    /* Firstly, get size of JSON and read it from file at once */
    fseek(json_file, 0, SEEK_END);
    size = ftell(json_file);
    fseek(json_file, 0, SEEK_SET);

    json_string = malloc(size);
    if(fread(json_string, size, 1, json_file) == 0) {
        perror("Failed to read config file");
        return_code -1;
        goto out;
    }

    /* Parse the JSON */
    config_json = cJSON_Parse(json_string);
    if (config_json == NULL) { 
        const char *error_ptr = cJSON_GetErrorPtr(); 
        if (error_ptr != NULL) { 
            printf("Failed to parse JSON: %s\n", error_ptr);
        }
        return_code = -1;
        goto out;
    } 

    /* Access the JSON data */ 
    blacklist_json = cJSON_GetObjectItemCaseSensitive(config_json, "blacklist"); 
    if (!cJSON_IsArray(blacklist_json)) { 
        printf("Invalid \"blacklist\" type\n");
        return_code = -1;
        goto out;
    }

    /* Allocate memory for array of addresses of black list */
    blacklist_size = cJSON_GetArraySize(blacklist_json);
    blacklist = malloc(blacklist_size * sizeof(const char *));

    /* Iterate over the black list and copy banned addresses */ 
    index = 0;
    cJSON_ArrayForEach(address_json, blacklist_json) {
        if (cJSON_IsString(address_json) && (address_json->valuestring != NULL)) {
            int len;
            blacklist[index] = malloc(HOSTNAME_SIZE);
            len = strlen(address_json->valuestring);
            strncpy(blacklist[index], address_json->valuestring, len);
            index++;
        }
    }

    upstream_server_json = cJSON_GetObjectItemCaseSensitive(config_json, "upstream_server");
    if (!cJSON_IsString(upstream_server_json)) { 
        printf("Invalid \"upstream_server\" type\n");
        return_code = -1;
        goto out;
    }
    strncpy(upstream_server_ip, upstream_server_json->valuestring, strlen(upstream_server_json->valuestring));

    response_msg_json = cJSON_GetObjectItemCaseSensitive(config_json, "response");
    if (!cJSON_IsString(upstream_server_json)) { 
        printf("Invalid \"response\" type\n");
        return_code = -1;
        goto out;
    }

    str_len = strlen(response_msg_json->valuestring);
    if (str_len > RESPONSE_SIZE) {
        printf("Error: \"response\" is too long. Maximum possible length = %d\n", RESPONSE_SIZE);
        return_code = -1;
        goto out;
    }
    strncpy(response_msg, response_msg_json->valuestring, str_len);

out:
    cJSON_Delete(config_json); 
    free(json_string);
    fclose(json_file);
    return return_code;
}

/**
 * @brief           Frees dynamically allocated global variables and resources
*/
void free_resources() {
    if (blacklist_size) {
        for (size_t i = 0; i < blacklist_size; i++) {
            free(blacklist[i]);
        }
        free(blacklist);
    }
}

/**
 * @brief           This function parses DNS request and extracts fields 
 * @param[in]       udp_packet: UDP packet which contains DNS request
 * @return          Returns 0 on success, or -1 if any errors
*/
int parse_dns_request(const char *udp_packet, struct parsed_dns_request *dns_req) {
    //struct parsed_dns_request *dns_req = NULL;

    //dns_req = (struct parsed_dns_request *)buffer; 
    /* Transaction ID */
    dns_req->transaction_id = (uint8_t)udp_packet[1] + (uint16_t)(udp_packet[0] << 8);
    udp_packet += sizeof(dns_req->transaction_id);
    
    /* Flags */
    dns_req->flags = (uint8_t)udp_packet[1] + (uint16_t)(udp_packet[0] << 8);
    udp_packet += sizeof(dns_req->flags);

    /* Questions num */
    dns_req->questions_num = (uint8_t)udp_packet[1] + (uint16_t)(udp_packet[0] << 8); 
    udp_packet += sizeof(dns_req->questions_num);

    /* Skipping 6 not interesting bytes 
       uint16_t Answers number 
       uint16_t Records number 
       uint16_t Additionals records number 
    */
    udp_packet+=6;
    
    /* Getting the dns query */
    bzero(dns_req->query, sizeof(dns_req->query));
    memcpy(dns_req->query, udp_packet, sizeof(dns_req->query) - 1);
    
    /* Hostname */
    bzero(dns_req->hostname, sizeof(dns_req->hostname));
    dns_req->hostname_len = 0;

    while (1) {
        uint8_t len; 
        
        len = udp_packet[0]; /* Length of the next label */
        if (len == 0) {
            dns_req->hostname[dns_req->hostname_len-1] = '\0';
            udp_packet++;
            break;
        }
        udp_packet++;
        if (dns_req->hostname_len + len >=  sizeof(dns_req->hostname)) {
            return -1;
        }
        strncat(dns_req->hostname, udp_packet, len); /* Append the current label to dns_req->hostname */
        strncat(dns_req->hostname, ".", 1); /* Append a '.' */
        dns_req->hostname_len+=len+1;
        udp_packet+=len;
    }

    /* Qtype */
    dns_req->qtype = (uint8_t)udp_packet[1] + (uint16_t)(udp_packet[0] << 8); 
    udp_packet+=2;

    /* Qclass */
    dns_req->qclass = (uint8_t)udp_packet[1] + (uint16_t)(udp_packet[0] << 8); 
    udp_packet+=2;
    return 0;
}

/**
 * @brief               Builds DNS response based on request for hostname from black list
 * @param[in]           sd: fd of server socket
 * @param[in]           client: address of reciever
 * @param[in]           dns_req: DNS request which was received from client 
*/
void send_dns_response(int sd, struct sockaddr_in client, struct parsed_dns_request *dns_req) {
    char *response = NULL, *response_ptr = NULL, *token = NULL;
    char client_ip[INET_ADDRSTRLEN];
    struct dns_header *header = NULL;
    struct dns_question *question = NULL;
    struct dns_rr *resource_record = NULL;
    size_t response_msg_length;
    ssize_t bytes_sent;
    
    /* Build DNS response */
    response = malloc (UDP_SIZE);
    bzero(response, UDP_SIZE);
    response_ptr = response;

    header = (struct dns_header *)response;

    /* Fill DNS header for answer */
    header->id = htons(dns_req->transaction_id);

    header->qr = 1;
    header->opcode = 0;
    header->aa = 0;
    header->tc = 0;
    header->rd = 1;
    header->ra = 0;
    header->z = 0;
    /* Return code = 3 (NXDOMAIN). It means that server couldn't resolve message */
    header->rcode = 3;

    header->q_count = htons(1);
    header->ans_count = 0;
    header->auth_count = 0;
    header->add_count = htons(1);

    response += sizeof(struct dns_header);

    /* Query */
    strncat(response, dns_req->query, dns_req->hostname_len);
    response+=dns_req->hostname_len+1;
    
    /* Type */
    question = (struct dns_question *)response;
    question->qtype = htons(dns_req->qtype);
    response+= sizeof(question->qtype);
    
    /* Class */
    question->qclass = htons(dns_req->qclass);
    response+=sizeof(question->qclass);
    
    /* Add message in additional section of DNS packet */
    response_msg_length = strlen(response_msg);
    resource_record = (struct dns_rr *)response;
    resource_record->name = htons(0xC00C);
    resource_record->type = htons(16); // TXT record type
    resource_record->_class = htons(1); // IN class
    resource_record->ttl = htonl(3600); // TTL
    resource_record->data_len = htons(response_msg_length + 1);
    response += sizeof(struct dns_rr);
    *response++ = response_msg_length;
    memcpy(response, response_msg, response_msg_length);
    response += response_msg_length;

    bytes_sent = sendto(sd, response_ptr, response - response_ptr, 0, (struct sockaddr *)&client, sizeof(client));
    fsync(sd);

    inet_ntop(AF_INET, &client.sin_addr, client_ip, sizeof(client_ip));
    printf("Dns response \"%s\" sent to the %s\n", response_msg, client_ip);
    free(response_ptr);
}

/**
 * @brief           Checks hostname if it's in black list
 * @return          Returns 1 if true, or 0 if false
*/
int is_banned(const char *hostname) {
    for (size_t i = 0; i < blacklist_size; i++) {
        if (strcmp(blacklist[i], hostname) == 0) {
            return 1;
        }
    }
    return 0;
}
