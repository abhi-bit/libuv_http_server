#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include "libuv/include/uv.h"
#include "http-parser/http_parser.h"

#define CHECK(r, msg) \
  if (r) { \
    std::cerr << msg << ": " << uv_strerror(r); \
    exit(1); \
  }

#define UVERR(err, msg) std::cerr << msg << ": " << uv_strerror(err);
#define LOG(msg) std::cout << msg;
#define LOGF(fmt, params...) printf(fmt "\n", params);
#define LOG_ERROR(msg) std::cout << msg;

#define HTTP_RESPONSE \
    "HTTP/1.1 200 OK\r\n" \
    "Content-Type: text/plain\r\n" \
    "Content-Length: 20\r\n" \
    "\r\n" \
    "hello from kubernets\n"

static uv_loop_t* uv_loop;
static uv_tcp_t server;
static http_parser_settings parser_settings;

static uv_buf_t resbuf;

typedef struct {
    uv_tcp_t handle;
    http_parser parser;
    uv_write_t write_req;
    int req_num;
} client_t;

void on_close(uv_handle_t *handle) {
    client_t* client = (client_t*) handle->data;
    LOGF("[ %5d ] connection closed", client->req_num);
    free(client);
}

void on_alloc(uv_handle_t* client, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    size_t parsed;

    client_t* client = (client_t*) stream->data;

    if (nread > 0) {
        parsed = http_parser_execute(
                &client->parser, &parser_settings, buf->base, nread);
        if (parsed < nread) {
            LOG_ERROR("parse error");
            uv_close((uv_handle_t*) &client->handle, on_close);
        }
    } else {
          LOG("read error");
    }
    free(buf->base);
}

static int req_num = 1;

void on_connect(uv_stream_t* server_handle, int status) {
    CHECK(status, "connect");

    int r;
    assert((uv_tcp_t*)server_handle == &server);

    client_t* client = (client_t*) malloc(sizeof(client_t));
    client->req_num = req_num;

    LOGF("[ %5d ] new connection", req_num++);

    uv_tcp_init(uv_loop, &client->handle);
    http_parser_init(&client->parser, HTTP_REQUEST);

    client->parser.data = client;
    client->handle.data = client;

    r = uv_accept(server_handle, (uv_stream_t *)&client->handle);
    CHECK(r, "accept");

    uv_read_start((uv_stream_t*) &client->handle, on_alloc, on_read);
}

void after_write(uv_write_t* req, int status) {
    CHECK(status, "write");
    uv_close((uv_handle_t*)req->handle, on_close);
}

int on_headers_complete(http_parser* parser) {
    client_t* client = (client_t*)parser->data;

    LOGF("[ %5d ] http message parsed", client->req_num);

    uv_write(
            &client->write_req,
            (uv_stream_t*)&client->handle,
            &resbuf,
            1,
            after_write);

    return 1;
}

int main() {
    int r;

    parser_settings.on_headers_complete = on_headers_complete;

    resbuf = uv_buf_init((char *)HTTP_RESPONSE, sizeof(HTTP_RESPONSE));

    uv_loop = uv_default_loop();

    r = uv_tcp_init(uv_loop, &server);
    CHECK(r, "uv_tcp_init");

    struct sockaddr_in addr;
    r = uv_ip4_addr("0.0.0.0", 8000, &addr);
    CHECK(r, "uv_ipv4_bind");

    // casting required from sockaddr_in to sockaddr
    r = uv_tcp_bind(&server, (const struct sockaddr*) &addr, 0);
    CHECK(r, "bind");
    uv_listen((uv_stream_t*) &server, 128, on_connect);

    LOG("listening on port 8000\n");

    uv_run(uv_loop, UV_RUN_DEFAULT);

    return 0;
}
