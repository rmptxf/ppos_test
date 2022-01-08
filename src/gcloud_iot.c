/* Gcloud iot implementation. */

#include <logging/log.h>

LOG_MODULE_DECLARE(ppos_gateway_app, LOG_LEVEL_DBG);

#include "gcloud_iot.h"
#include <stdio.h>
#include <zephyr.h>
#include <string.h>
#include <modem/modem_jwt.h>
#include <drivers/entropy.h>
#include <net/mqtt.h>

#include <net/socket.h>
#include <modem/at_cmd.h>
#include <modem/lte_lc.h>

//static struct mqtt_publish_param pub_data = {0};

/* The mqtt client struct */
static struct mqtt_client client;

/* MQTT Broker details. */
static struct sockaddr_storage broker;

/* Buffers for MQTT client. */
static uint8_t rx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];
static uint8_t tx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];
static uint8_t payload_buf[CONFIG_MQTT_PAYLOAD_BUFFER_SIZE];

/* Jwt buffer. */
char jwt_buffer[CONFIG_MODEM_JWT_MAX_LEN] = {0};

static struct mqtt_utf8 jwt_token = {
	.utf8 = jwt_buffer
};

static struct mqtt_utf8 username = {
	.utf8 = "unused",
	.size = sizeof("unused")
};

/**@brief Function to print strings without null-termination
 */
static void data_print(uint8_t *prefix, uint8_t *data, size_t len)
{
	char buf[len + 1];

	memcpy(buf, data, len);
	buf[len] = 0;
	LOG_INF("%s%s", log_strdup(prefix), log_strdup(buf));
}

/**@brief Function to publish data on the configured topic
 */
static int data_publish( struct mqtt_client *c, 
                         enum mqtt_qos qos,
	                     uint8_t *data, size_t len)
{
	struct mqtt_publish_param params;

	params.message.topic.qos = qos;
	params.message.topic.topic.utf8 = CONFIG_CLOUD_PUB_TOPIC;
	params.message.topic.topic.size = strlen(CONFIG_CLOUD_PUB_TOPIC);
	params.message.payload.data = data;
	params.message.payload.len = len;
	params.message_id = CONFIG_PUBLISH_ID;
	params.dup_flag = 0;
	params.retain_flag = 0;

	data_print("Publishing: ", data, len);

	LOG_INF("to topic: %s len: %u",
		CONFIG_CLOUD_PUB_TOPIC,
		(unsigned int)strlen(CONFIG_CLOUD_PUB_TOPIC));

	return mqtt_publish(c, &params);
}

/**@brief Function to subscribe to the configured topic
 */
static int subscribe(void)
{
	struct mqtt_topic subscribe_topic = {
		.topic = {
			.utf8 = CONFIG_CLOUD_SUB_TOPIC,
			.size = strlen(CONFIG_CLOUD_SUB_TOPIC)
		},
		.qos = MQTT_QOS_1_AT_LEAST_ONCE
	};

	const struct mqtt_subscription_list subscription_list = {
		.list = &subscribe_topic,
		.list_count = 1,
		.message_id = CONFIG_SUBSCRIBE_ID
	};

	LOG_INF("Subscribing to: %s len %u", CONFIG_CLOUD_SUB_TOPIC,
		(unsigned int)strlen(CONFIG_CLOUD_SUB_TOPIC));

	return mqtt_subscribe(&client, &subscription_list);
}

/**@brief Function to read the published payload.
 */
static int publish_get_payload(struct mqtt_client *c, size_t length)
{
	if (length > sizeof(payload_buf)) {
		return -EMSGSIZE;
	}

	return mqtt_readall_publish_payload(c, payload_buf, length);
}

/**@brief MQTT client event handler
 */
static void mqtt_evt_handler(struct mqtt_client *const c,
		      		  const struct mqtt_evt *evt)
{
	int err;

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT connect failed: %d", evt->result);
			break;
		}

		LOG_INF("MQTT client connected");
		err = subscribe();
		if(err)
		{
			LOG_ERR("Error subscribing to the SUB topic, err: %d", err);
		}
		LOG_INF("Subscribed successfully to the SUB topic.");
		
		break;

	case MQTT_EVT_DISCONNECT:
		LOG_INF("MQTT client disconnected: %d", evt->result);
		break;

	case MQTT_EVT_PUBLISH: {
		const struct mqtt_publish_param *p = &evt->param.publish;

		LOG_INF("MQTT PUBLISH result=%d len=%d",
			evt->result, p->message.payload.len);
		err = publish_get_payload(c, p->message.payload.len);

		if (p->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
			const struct mqtt_puback_param ack = {
				.message_id = p->message_id
			};

			/* Send acknowledgment. */
			mqtt_publish_qos1_ack(&client, &ack);
		}

		if (err >= 0) {
			data_print("Received: ", payload_buf,
				p->message.payload.len);
			/* Echo back received data */
			data_publish(&client, MQTT_QOS_1_AT_LEAST_ONCE,
				payload_buf, p->message.payload.len);
		} else {
			LOG_ERR("publish_get_payload failed: %d", err);
			LOG_INF("Disconnecting MQTT client...");

			err = mqtt_disconnect(c);
			if (err) {
				LOG_ERR("Could not disconnect: %d", err);
			}
		}
	} break;

	case MQTT_EVT_PUBACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT PUBACK error: %d", evt->result);
			break;
		}

		LOG_INF("PUBACK packet id: %u", evt->param.puback.message_id);
		break;

	case MQTT_EVT_SUBACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT SUBACK error: %d", evt->result);
			break;
		}

		LOG_INF("SUBACK packet id: %u", evt->param.suback.message_id);
		break;

	case MQTT_EVT_PINGRESP:
		if (evt->result != 0) {
			LOG_ERR("MQTT PINGRESP error: %d", evt->result);
		}
		break;

	default:
		LOG_INF("Unhandled MQTT event type: %d", evt->type);
		break;
	}
}

/**@brief Resolves the configured hostname and
 * initializes the MQTT broker structure
 */
static int broker_init(void)
{
	int err;
	struct addrinfo *result;
	struct addrinfo *addr;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM
	};

	err = getaddrinfo(CONFIG_CLOUD_BROKER_HOSTNAME, "8883", &hints, &result);
	if (err) {
		LOG_ERR("getaddrinfo failed: [%d] %s", err, strerror(err));
		return -ECHILD;
	}

	addr = result;

	/* Look for address of the broker. */
	while (addr != NULL) {
		/* IPv4 Address. */
		if (addr->ai_addrlen == sizeof(struct sockaddr_in)) {
			struct sockaddr_in *broker4 =
				((struct sockaddr_in *)&broker);

			char ipv4_addr[NET_IPV4_ADDR_LEN];

			broker4->sin_addr.s_addr =
				((struct sockaddr_in *)addr->ai_addr)
				->sin_addr.s_addr;
			broker4->sin_family = AF_INET;
			broker4->sin_port = htons(CONFIG_CLOUD_BROKER_PORT);

			inet_ntop(AF_INET, &broker4->sin_addr.s_addr,
				  ipv4_addr, sizeof(ipv4_addr));

			LOG_INF("IPv4 Address found %s", log_strdup(ipv4_addr));

			break;
		} else {
			LOG_ERR("ai_addrlen = %u should be %u or %u",
				(unsigned int)addr->ai_addrlen,
				(unsigned int)sizeof(struct sockaddr_in),
				(unsigned int)sizeof(struct sockaddr_in6));
		}

		addr = addr->ai_next;
		break;
	}

	/* Free the address. */
	freeaddrinfo(result);
	return 0;
}


/* Function to generate a Json web token */
static int jwt_generate(char *buffer, size_t buffer_size)
{
	int err;
	struct jwt_data jwt = {0};
	jwt.audience = CONFIG_CLOUD_AUDIENCE;
	jwt.exp_delta_s = 86400;  /* 24 hours = 86400 seconds */
	jwt.sec_tag = CONFIG_CLIENT_SEC_TAG; /* Private key security tag */
	jwt.key = JWT_KEY_TYPE_CLIENT_PRIV; /* key type */
	jwt.alg = JWT_ALG_TYPE_ES256;

	err = modem_jwt_generate(&jwt);
	memcpy(buffer, jwt.jwt_buf, strlen(jwt.jwt_buf));
	buffer_size = strlen(jwt.jwt_buf);

	return err;
}

/**@brief Initialize the MQTT client structure
 */
static int client_init(struct mqtt_client *client)
{
	int err;

	mqtt_client_init(client);

	err = broker_init();
	if (err) {
		LOG_ERR("Failed to initialize broker connection, err: [%d] %s", err, strerror(-err));
		return err;
	}

	err = jwt_generate(jwt_buffer, CONFIG_MODEM_JWT_MAX_LEN);
	if (err) {
		LOG_ERR("Failed to generate a jwt, err: [%d] %s", err, strerror(-err));
		return err;
	}

    LOG_INF("JWT generated.");

	jwt_token.size = strlen(jwt_buffer);

	/* MQTT client configuration */
	client->broker = &broker;
	client->evt_cb = mqtt_evt_handler;
	client->client_id.utf8 = (uint8_t*)CONFIG_CLOUD_CLIENT_ID;
	client->client_id.size = strlen(CONFIG_CLOUD_CLIENT_ID);
	client->password = &jwt_token;
	client->user_name = &username;
	client->protocol_version = MQTT_VERSION_3_1_1;
	client->transport.type = MQTT_TRANSPORT_SECURE;

	/* MQTT buffers configuration */
	client->rx_buf = rx_buffer;
	client->rx_buf_size = sizeof(rx_buffer);
	client->tx_buf = tx_buffer;
	client->tx_buf_size = sizeof(tx_buffer);

	/* MQTT transport configuration */
	struct mqtt_sec_config *tls_cfg = &(client->transport).tls.config;

	/* Google CA Certifications tags */
	static sec_tag_t m_sec_tags[] = {
		CONFIG_GOOGLE_CA_CERT_1_SEC_TAG,
		CONFIG_GOOGLE_CA_CERT_2_SEC_TAG
	};

	tls_cfg->peer_verify = CONFIG_MQTT_TLS_PEER_VERIFY;
	tls_cfg->cipher_count = 0;
	tls_cfg->cipher_list = NULL;
	tls_cfg->sec_tag_count = ARRAY_SIZE(m_sec_tags);
	tls_cfg->sec_tag_list = m_sec_tags;
	tls_cfg->hostname = CONFIG_CLOUD_BROKER_HOSTNAME;

	#if defined(CONFIG_NRF_MODEM_LIB)
		tls_cfg->session_cache = IS_ENABLED(CONFIG_MQTT_TLS_SESSION_CACHING) ?
							TLS_SESSION_CACHE_ENABLED :
							TLS_SESSION_CACHE_DISABLED;
	#else
		/* TLS session caching is not supported by the Zephyr network stack */
		tls_cfg->session_cache = TLS_SESSION_CACHE_DISABLED;
	#endif

	return err;
}

int gcloud_iot_client_init(void)
{
	int err;

	err = client_init(&client);
	if(err) return err;

	LOG_INF("Trying to connect to the gcloud..");

	err = mqtt_connect(&client);
	if (err){
		LOG_ERR("mqtt_connect , err: [%d] %s", err, strerror(-err));
	}

	LOG_INF("gcloud connected");

	return err;
}