/*
 *   purple-chimp
 *   Copyright (C) 2018  dequis
 *   Copyright (C) 2016  Eion Robb
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Glib
#include <glib.h>

// GNU C libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
	#include <unistd.h>
#endif
#include <errno.h>

#include <json-glib/json-glib.h>
// Supress overzealous json-glib 'critical errors'
#define json_object_get_int_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_int_member(JSON_OBJECT, MEMBER) : 0)
#define json_object_get_string_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_string_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_array_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_array_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_object_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_object_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_boolean_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_boolean_member(JSON_OBJECT, MEMBER) : FALSE)


#include <purple.h>
#include "http.h"

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#ifndef _
#	define _(a) (a)
#	define N_(a) (a)
#endif

#define CHIMP_PLUGIN_ID "prpl-dequis-chimp"
#ifndef CHIMP_PLUGIN_VERSION
#define CHIMP_PLUGIN_VERSION "0.1"
#endif
#define CHIMP_PLUGIN_WEBSITE "https://github.com/dequis/purple-chimp"

#define CHIMP_USERAGENT "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

#define CHIMP_BUFFER_DEFAULT_SIZE 40960


#include "purplecompat.h"
#include "glibcompat.h"

// Purple2 compat functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)

void _purple_socket_init(void);
void _purple_socket_uninit(void);

#define purple_buddy_set_name  purple_blist_rename_buddy

#endif


typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	gchar *session_token;
	gchar *url_msg;
	gchar *url_profile;
	gchar *url_contacts;
	gchar *url_websocket;
	
	PurpleSslConnection *websocket;
	gboolean websocket_header_received;
	gboolean sync_complete;
	guchar packet_code;
	gchar *frame;
	guint64 frame_len;
	guint64 frame_len_progress;
	
	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gint frames_since_reconnect;
	GSList *pending_writes;
} ChimpAccount;

typedef void (*ChimpProxyCallbackFunc)(ChimpAccount *ya, JsonNode *node, gpointer user_data);

typedef struct {
	ChimpAccount *ya;
	ChimpProxyCallbackFunc callback;
	gpointer user_data;
} ChimpProxyConnection;


gchar *
chimp_string_get_chunk(const gchar *haystack, gsize len, const gchar *start, const gchar *end)
{
	const gchar *chunk_start, *chunk_end;
	g_return_val_if_fail(haystack && start && end, NULL);
	
	if (len > 0) {
		chunk_start = g_strstr_len(haystack, len, start);
	} else {
		chunk_start = strstr(haystack, start);
	}
	g_return_val_if_fail(chunk_start, NULL);
	chunk_start += strlen(start);
	
	if (len > 0) {
		chunk_end = g_strstr_len(chunk_start, len - (chunk_start - haystack), end);
	} else {
		chunk_end = strstr(chunk_start, end);
	}
	g_return_val_if_fail(chunk_end, NULL);
	
	return g_strndup(chunk_start, chunk_end - chunk_start);
}

JsonNode *
chimp_json_path_query(JsonNode *root, const gchar *expr, GError **error)
{
	JsonNode *ret;
	JsonNode *node;
	JsonArray *result;

	if (g_str_equal(expr, "$")) {
		return root;
	}

	node = json_path_query(expr, root, error);

	if (error != NULL) {
		json_node_free(node);
		return NULL;
	}

	result = json_node_get_array(node);
	if (json_array_get_length(result) == 0) {
		json_node_free(node);
		return NULL;
	}
	ret = json_array_dup_element(result, 0);
	json_node_free(node);
	return ret;

}

gchar *
chimp_json_path_query_string(JsonNode *root, const gchar *expr, GError **error)
{
	gchar *ret;
	JsonNode *rslt;

	rslt = chimp_json_path_query(root, expr, error);

	if (rslt == NULL) {
		return NULL;
	}

	ret = g_strdup(json_node_get_string(rslt));
	json_node_free(rslt);
	return ret;
}

gint64
chimp_json_path_query_int(JsonNode *root, const gchar *expr, GError **error)
{
	gint64 ret;
	JsonNode *rslt;

	rslt = chimp_json_path_query(root, expr, error);

	if (rslt == NULL) {
		return 0;
	}

	ret = json_node_get_int(rslt);
	json_node_free(rslt);
	return ret;
}


static void
chimp_response_callback(PurpleHttpConnection *http_conn, PurpleHttpResponse *response, gpointer user_data)
{
	const gchar *body;
	gsize body_len;
	ChimpProxyConnection *conn = user_data;
	
	conn->ya->http_conns = g_slist_remove(conn->ya->http_conns, http_conn);

	if (!purple_http_response_is_successful(response)) {
		purple_connection_error(conn->ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, purple_http_response_get_error(response));
		g_free(conn);
		return;
	}

	JsonParser *parser = json_parser_new();
	body = purple_http_response_get_data(response, &body_len);
	
	if (!json_parser_load_from_data(parser, body, body_len, NULL))
	{
		purple_debug_error("chimp", "Error parsing response: %s\n", body);
		if (conn->callback) {
			conn->callback(conn->ya, NULL, conn->user_data);
		}
	} else {
		JsonNode *root = json_parser_get_root(parser);
		
		purple_debug_misc("chimp", "Got response: %s\n", body);
		if (conn->callback) {
			conn->callback(conn->ya, root, conn->user_data);
		}
	}
	
	g_object_unref(parser);
	g_free(conn);
}

static PurpleHttpRequest *
chimp_prepare_fetch_url(ChimpAccount *ya, const gchar *url, const gchar *postdata)
{
	purple_debug_info("chimp", "Fetching url %s\n", url);

	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "User-Agent", CHIMP_USERAGENT);

	if (ya->session_token) {
		char *val = g_strconcat("_aws_wt_session=", ya->session_token, NULL);
		purple_http_request_header_set(request, "Cookie", val);
		g_free(val);
	}
	
	if (postdata) {
		purple_debug_info("chimp", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			purple_http_request_header_set(request, "Content-Type", "application/json");
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}
		purple_http_request_set_contents(request, postdata, -1);
		purple_http_request_set_method(request, "POST");
	}
	
	return request;
}

static void
chimp_fetch_url(ChimpAccount *ya, const gchar *url, const gchar *postdata, ChimpProxyCallbackFunc callback, gpointer user_data)
{
	ChimpProxyConnection *conn;
	PurpleHttpRequest *request;

	if (purple_account_is_disconnected(ya->account)) return;

	conn = g_new0(ChimpProxyConnection, 1);
	conn->ya = ya;
	conn->callback = callback;
	conn->user_data = user_data;

	request = chimp_prepare_fetch_url(ya, url, postdata);

	purple_http_request(ya->pc, request, chimp_response_callback, conn);
	purple_http_request_unref(request);

	// TODO: add something to ya->http_conns
}

static void chimp_socket_write_json(ChimpAccount *ya, JsonObject *data);

static void chimp_start_socket(ChimpAccount *ya);

static void
chimp_restart_channel(ChimpAccount *ya)
{
	purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTING);
	//chimp_fetch_url(ya, "TODO", rpcdata, chimp_rpc_callback, NULL);
}

static void
chimp_auth_callback(ChimpAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	JsonObject *session = json_object_get_object_member(obj, "Session");
	JsonNode *config = json_object_get_member(session, "ServiceConfig");
	const char *stoken = json_object_get_string_member(session, "SessionToken");

	ya->session_token = g_strdup(stoken);

	ya->url_msg = chimp_json_path_query_string(config, "$.Messaging.RestUrl", NULL);
	ya->url_profile = chimp_json_path_query_string(config, "$.Profile.RestUrl", NULL);
	ya->url_contacts = chimp_json_path_query_string(config, "$.Contacts.RestUrl", NULL);
	ya->url_websocket = chimp_json_path_query_string(config, "$.Push.WebsocketUrl", NULL);

	purple_serv_got_im(ya->pc, "test", "success", 0, 0);

	purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTED);
}

static void
chimp_login(PurpleAccount *account)
{
	ChimpAccount *ya;
	PurpleConnection *pc = purple_account_get_connection(account);
	
	ya = g_new0(ChimpAccount, 1);
	purple_connection_set_protocol_data(pc, ya);
	ya->account = account;
	ya->pc = pc;
	
	purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTING);

	char *url = g_strconcat("https://signin.id.ue1.app.chime.aws/sessions?Token=", purple_url_encode(purple_connection_get_password(pc)), NULL);
	const char *payload = "{\"Device\":{\"Platform\":\"android\",\"DeviceToken\":\"foo\",\"PlatformDeviceId\":\"bar\", \"Capabilities\":0}}";

	chimp_fetch_url(ya, url, payload, chimp_auth_callback, NULL);

	g_free(url);
}


static void 
chimp_close(PurpleConnection *pc)
{
	ChimpAccount *ya = purple_connection_get_protocol_data(pc);
	
	g_return_if_fail(ya != NULL);
	
	if (ya->websocket != NULL) purple_ssl_close(ya->websocket);
	
	while (ya->http_conns) {
		purple_http_conn_cancel(ya->http_conns->data);
	}

	while (ya->pending_writes) {
		json_object_unref(ya->pending_writes->data);
		ya->pending_writes = g_slist_delete_link(ya->pending_writes, ya->pending_writes);
	}

	g_free(ya->frame);
	g_free(ya->session_token);
	g_free(ya->url_msg);
	g_free(ya->url_profile);
	g_free(ya->url_contacts);
	g_free(ya->url_websocket);

	g_free(ya);
}








static gboolean
chimp_process_frame(ChimpAccount *ya, const gchar *frame)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;
	
	purple_debug_info("chimp", "got frame data: %s\n", frame);
	
	if (!json_parser_load_from_data(parser, frame, -1, NULL))
	{
		purple_debug_error("chimp", "Error parsing response: %s\n", frame);
		return TRUE;
	}
	
	root = json_parser_get_root(parser);
	
	if (root != NULL) {
		// TODO
	}
	ya->frames_since_reconnect += 1;
	
	g_object_unref(parser);
	return TRUE;
}

static guchar *
chimp_websocket_mask(guchar key[4], const guchar *pload, guint64 psize)
{
	guint64 i;
	guchar *ret = g_new0(guchar, psize);

	for (i = 0; i < psize; i++) {
		ret[i] = pload[i] ^ key[i % 4];
	}

	return ret;
}

static void
chimp_socket_write_data(ChimpAccount *ya, guchar *data, gsize data_len, guchar type)
{
	guchar *full_data;
	guint len_size = 1;
	guchar mkey[4] = { 0x12, 0x34, 0x56, 0x78 };
	
	if (data_len) {
		purple_debug_info("chimp", "sending frame: %*s\n", (int)data_len, data);
	}
	
	data = chimp_websocket_mask(mkey, data, data_len);
	
	if (data_len > 125) {
		if (data_len <= G_MAXUINT16) {
			len_size += 2;
		} else {
			len_size += 8;
		}
	}
	full_data = g_new0(guchar, 1 + data_len + len_size + 4);
	
	if (type == 0) {
		type = 129;
	}
	full_data[0] = type;
	
	if (data_len <= 125) {
		full_data[1] = data_len | 0x80;
	} else if (data_len <= G_MAXUINT16) {
		guint16 be_len = GUINT16_TO_BE(data_len);
		full_data[1] = 126 | 0x80;
		memmove(full_data + 2, &be_len, 2);
	} else {
		guint64 be_len = GUINT64_TO_BE(data_len);
		full_data[1] = 127 | 0x80;
		memmove(full_data + 2, &be_len, 8);
	}
	
	memmove(full_data + (1 + len_size), &mkey, 4);
	memmove(full_data + (1 + len_size + 4), data, data_len);
	
	purple_ssl_write(ya->websocket, full_data, 1 + data_len + len_size + 4);
	
	g_free(full_data);
	g_free(data);
}

/* takes ownership of data parameter */
static void
chimp_socket_write_json(ChimpAccount *ya, JsonObject *data)
{
	JsonNode *node;
	JsonObject *object;
	JsonArray *data_array;
	JsonArray *inner_data_array;
	gchar *str;
	gsize len;
	JsonGenerator *generator;
	
	if (ya->websocket == NULL) {
		if (data != NULL) {
			ya->pending_writes = g_slist_append(ya->pending_writes, data);
		}
		return;
	}
	
	data_array = json_array_new();
	
	if (data != NULL) {
		inner_data_array = json_array_new();
		json_array_add_object_element(inner_data_array, data);
		json_array_add_array_element(data_array, inner_data_array);
	}
	
	object = json_object_new();
	json_object_set_array_member(object, "data", data_array);
	
	node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(node, object);
	
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, &len);
	g_object_unref(generator);
	
	chimp_socket_write_data(ya, (guchar *)str, len, 0);
	
	g_free(str);
	json_node_free(node);
	json_object_unref(object);
}

static void
chimp_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	ChimpAccount *ya = userdata;
	guchar length_code;
	int read_len = 0;
	gboolean done_some_reads = FALSE;
	
	
	if (G_UNLIKELY(!ya->websocket_header_received)) {
		// HTTP/1.1 101 Switching Protocols
		// Server: nginx
		// Date: Sun, 19 Jul 2015 23:44:27 GMT
		// Connection: upgrade
		// Upgrade: websocket
		// Sec-WebSocket-Accept: pUDN5Js0uDN5KhEWoPJGLyTqwME=
		// Expires: 0
		// Cache-Control: no-cache
		gint nlbr_count = 0;
		gchar nextchar;
		
		while(nlbr_count < 4 && purple_ssl_read(conn, &nextchar, 1)) {
			if (nextchar == '\r' || nextchar == '\n') {
				nlbr_count++;
			} else {
				nlbr_count = 0;
			}
		}
		
		ya->websocket_header_received = TRUE;
		done_some_reads = TRUE;

		/* flush stuff that we attempted to send before the websocket was ready */
		while (ya->pending_writes) {
			chimp_socket_write_json(ya, ya->pending_writes->data);
			ya->pending_writes = g_slist_delete_link(ya->pending_writes, ya->pending_writes);
		}
	}
	
	while(ya->frame || (read_len = purple_ssl_read(conn, &ya->packet_code, 1)) == 1) {
		if (!ya->frame) {
			if (ya->packet_code != 129) {
				if (ya->packet_code == 136) {
					purple_debug_error("chimp", "websocket closed\n");
					
					// Try reconnect
					chimp_start_socket(ya);
					
					return;
				} else if (ya->packet_code == 137) {
					// Ping
					gint ping_frame_len;
					length_code = 0;
					purple_ssl_read(conn, &length_code, 1);
					if (length_code <= 125) {
						ping_frame_len = length_code;
					} else if (length_code == 126) {
						guchar len_buf[2];
						purple_ssl_read(conn, len_buf, 2);
						ping_frame_len = (len_buf[0] << 8) + len_buf[1];
					} else if (length_code == 127) {
						purple_ssl_read(conn, &ping_frame_len, 8);
						ping_frame_len = GUINT64_FROM_BE(ping_frame_len);
					}
					if (ping_frame_len) {
						guchar *pong_data = g_new0(guchar, ping_frame_len);
						purple_ssl_read(conn, pong_data, ping_frame_len);

						chimp_socket_write_data(ya, pong_data, ping_frame_len, 138);
						g_free(pong_data);
					} else {
						chimp_socket_write_data(ya, (guchar *) "", 0, 138);
					}
					return;
				} else if (ya->packet_code == 138) {
					// Pong
					//who cares
					return;
				} else if (ya->packet_code == '{') {
					// They've provided us a JSON response!
					purple_debug_error("chimp", "json response given to websocket channel\n");
					
					// Try reconnect
					chimp_start_socket(ya);
					
					return;
				}
				purple_debug_error("chimp", "unknown websocket error %d\n", ya->packet_code);
				return;
			}
			
			length_code = 0;
			purple_ssl_read(conn, &length_code, 1);
			if (length_code <= 125) {
				ya->frame_len = length_code;
			} else if (length_code == 126) {
				guchar len_buf[2];
				purple_ssl_read(conn, len_buf, 2);
				ya->frame_len = (len_buf[0] << 8) + len_buf[1];
			} else if (length_code == 127) {
				purple_ssl_read(conn, &ya->frame_len, 8);
				ya->frame_len = GUINT64_FROM_BE(ya->frame_len);
			}
			purple_debug_info("chimp", "frame_len: %" G_GUINT64_FORMAT "\n", ya->frame_len);
			
			ya->frame = g_new0(gchar, ya->frame_len + 1);
			ya->frame_len_progress = 0;
		}
		
		do {
			read_len = purple_ssl_read(conn, ya->frame + ya->frame_len_progress, ya->frame_len - ya->frame_len_progress);
			if (read_len > 0) {
				ya->frame_len_progress += read_len;
			}
		} while (read_len > 0 && ya->frame_len_progress < ya->frame_len);
		done_some_reads = TRUE;
		
		if (ya->frame_len_progress == ya->frame_len) {
			gboolean success = chimp_process_frame(ya, ya->frame);
			g_free(ya->frame); ya->frame = NULL;
			ya->packet_code = 0;
			ya->frame_len = 0;
			
			if (G_UNLIKELY(ya->websocket == NULL || success == FALSE)) {
				return;
			}
		} else {
			return;
		}
	}

	if (done_some_reads == FALSE && read_len <= 0) {
		if (read_len < 0 && errno == EAGAIN) {
			return;
		}

		purple_debug_error("chimp", "got errno %d, read_len %d from websocket thread\n", errno, read_len);

		if (ya->frames_since_reconnect < 2) {
			purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Lost connection to server");
		} else {
			// Try reconnect
			chimp_start_socket(ya);
		}
	}
}

static void
chimp_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	ChimpAccount *ya = userdata;
	gchar *websocket_header;
	gchar *host, *path;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; //TODO don't be lazy

	purple_url_parse(ya->url_websocket, &host, NULL, &path, NULL, NULL);
	
	purple_ssl_input_add(ya->websocket, chimp_socket_got_data, ya);
	
	websocket_header = g_strdup_printf("GET %s HTTP/1.1\r\n"
							"Host: %s\r\n"
							"Connection: Upgrade\r\n"
							"Pragma: no-cache\r\n"
							"Cache-Control: no-cache\r\n"
							"Upgrade: websocket\r\n"
							"Sec-WebSocket-Version: 13\r\n"
							"Sec-WebSocket-Key: %s\r\n"
							"User-Agent: " CHIMP_USERAGENT "\r\n"
							"\r\n", path, host, websocket_key);
	
	purple_ssl_write(ya->websocket, websocket_header, strlen(websocket_header));
	
	g_free(host);
	g_free(path);
	g_free(websocket_header);
}

static void
chimp_socket_failed(PurpleSslConnection *conn, PurpleSslErrorType errortype, gpointer userdata)
{
	ChimpAccount *ya = userdata;
	
	ya->websocket = NULL;
	ya->websocket_header_received = FALSE;
	
	chimp_restart_channel(ya);
}

static void
chimp_start_socket(ChimpAccount *ya)
{
	//Reset all the old stuff
	if (ya->websocket != NULL) {
		purple_ssl_close(ya->websocket);
	}
	
	ya->websocket = NULL;
	ya->websocket_header_received = FALSE;
	g_free(ya->frame); ya->frame = NULL;
	ya->packet_code = 0;
	ya->frame_len = 0;
	ya->frames_since_reconnect = 0;

	ya->websocket = purple_ssl_connect(ya->account, "ws12.cl.psh.ue1.app.chime.aws", 443, chimp_socket_connected, chimp_socket_failed, ya);
}


static gint
chimp_conversation_send_message(ChimpAccount *ya, const gchar *groupId, const gchar *message)
{
	JsonObject *data = json_object_new();
	gchar *stripped;
	
	json_object_set_string_member(data, "msg", "InsertItem");
	json_object_set_string_member(data, "groupId", groupId);
	
	stripped = g_strstrip(purple_markup_strip_html(message));
	json_object_set_string_member(data, "message", stripped);
	g_free(stripped);
	
	chimp_socket_write_json(ya, data);
	
	return 1;
}

static int
chimp_send_im(PurpleConnection *pc, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif

	ChimpAccount *ya = purple_connection_get_protocol_data(pc);
	
	return chimp_conversation_send_message(ya, who, message);
}

static const char *
chimp_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "chimp";
}

static GList *
chimp_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;

	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "online", "Online", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	return types;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);
	
	return TRUE;
}

// Purple2 Plugin Load Functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)
static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	_purple_socket_init();
	purple_http_init();

	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	_purple_socket_uninit();
	purple_http_uninit();

	return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{
	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);
	
	info = plugin->info;
	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}
	info->extra_info = prpl_info;
	#if PURPLE_MINOR_VERSION >= 5
		prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
	#endif
	#if PURPLE_MINOR_VERSION >= 8
		//prpl_info->add_buddy_with_invite = chimp_add_buddy_with_invite;
	#endif
	
	prpl_info->options = OPT_PROTO_SLASH_COMMANDS_NATIVE;
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;
	
	prpl_info->list_icon = chimp_list_icon;
	prpl_info->status_types = chimp_status_types;
	prpl_info->login = chimp_login;
	prpl_info->close = chimp_close;
	prpl_info->send_im = chimp_send_im;
	
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
/*	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL, /* type */
	NULL, /* ui_requirement */
	0, /* flags */
	NULL, /* dependencies */
	PURPLE_PRIORITY_DEFAULT, /* priority */
	CHIMP_PLUGIN_ID, /* id */
	"Chimp", /* name */
	CHIMP_PLUGIN_VERSION, /* version */
	"", /* summary */
	"", /* description */
	"dequis <dx@dxzone.com.ar>", /* author */
	CHIMP_PLUGIN_WEBSITE, /* homepage */
	libpurple2_plugin_load, /* load */
	libpurple2_plugin_unload, /* unload */
	NULL, /* destroy */
	NULL, /* ui_info */
	NULL, /* extra_info */
	NULL, /* prefs_info */
	NULL/*plugin_actions*/, /* actions */
	NULL, /* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(chimp, plugin_init, info);

#else
//Purple 3 plugin load functions


G_MODULE_EXPORT GType chimp_protocol_get_type(void);
#define CHIMP_TYPE_PROTOCOL			(chimp_protocol_get_type())
#define CHIMP_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), CHIMP_TYPE_PROTOCOL, ChimpProtocol))
#define CHIMP_PROTOCOL_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), CHIMP_TYPE_PROTOCOL, ChimpProtocolClass))
#define CHIMP_IS_PROTOCOL(obj)		(G_TYPE_CHECK_INSTANCE_TYPE((obj), CHIMP_TYPE_PROTOCOL))
#define CHIMP_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), CHIMP_TYPE_PROTOCOL))
#define CHIMP_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), CHIMP_TYPE_PROTOCOL, ChimpProtocolClass))

typedef struct _ChimpProtocol
{
	PurpleProtocol parent;
} ChimpProtocol;

typedef struct _ChimpProtocolClass
{
	PurpleProtocolClass parent_class;
} ChimpProtocolClass;

static void
chimp_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;

	info->id = CHIMP_PLUGIN_ID;
	info->name = "Chimp";
}

static void
chimp_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = chimp_login;
	prpl_info->close = chimp_close;
	prpl_info->status_types = chimp_status_types;
	prpl_info->list_icon = chimp_list_icon;
}

static void 
chimp_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = chimp_send_im;
}

static PurpleProtocol *chimp_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	ChimpProtocol, chimp_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  chimp_protocol_im_iface_init)
);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	chimp_protocol_register_type(plugin);
	chimp_protocol = purple_protocols_add(CHIMP_TYPE_PROTOCOL, error);
	if (!chimp_protocol)
		return FALSE;

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(chimp_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          CHIMP_PLUGIN_ID,
		"name",        "Chimp",
		"version",     CHIMP_PLUGIN_VERSION,
		"category",    N_("Protocol"),
		"summary",     N_("Chimp Protocol Plugins."),
		"description", N_("Adds Amazon Chime protocol support to libpurple."),
		"website",     CHIMP_PLUGIN_WEBSITE,
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(chimp, plugin_query,
		libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
