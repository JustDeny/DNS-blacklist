#include <netinet/in.h>

#define DNS_PORT 53
#define UDP_SIZE 1024
#define HOSTNAME_SIZE 128
#define IP_STR_SIZE 16
#define RESPONSE_SIZE 255

/* Disable struct alignment in order to properly map DNS packet fields to buffer */
#pragma pack(push, 1)

/**
 * @brief           Represents structure and fields of DNS header
*/
struct dns_header
{
    unsigned short id;
 
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
 
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
 
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
};

/**
 * @brief           Represents fields of DNS question segment
 */
struct dns_question {
    /* before qtype must be qname field, but it has variable length that's why skiped here */
    unsigned short qtype;
    unsigned short qclass;
};

/**
 * @brief           Represents fields of DNS resource record segment
 * @note            Can be used to left custom message in built DNS response (see send_dns_response)
*/
struct dns_rr {
    /* before type must be name field as well as in question section was skiped */
    unsigned short name;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

/**
 * @brief           This structure is used to store values extracted from query fields
*/
struct parsed_dns_request {
    uint16_t transaction_id,
             questions_num,
             flags,
             qtype,
             qclass;
    char hostname[HOSTNAME_SIZE],
         query[128];
    size_t hostname_len;
};

void sigint_handler(int sg);
int init_server_socket();
int load_config();
void free_resources();
int parse_dns_request(const char *udp_packet,  struct parsed_dns_request *dns_req);
int is_banned(const char *hostname);
void send_dns_response(int sd, struct sockaddr_in client, struct parsed_dns_request *dns_req);