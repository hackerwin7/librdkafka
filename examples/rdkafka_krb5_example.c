#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <unistd.h>

#include "librdkafka/rdkafka.h"

void logger(const rd_kafka_t *rk, int level,
            const char *fac, const char *buf) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    fprintf(stderr, "%u.%03u RDKAFKA-%i-%s: %s: %s\n",
            (int) tv.tv_sec, (int) (tv.tv_usec / 1000),
            level, fac, rk ? rd_kafka_name(rk) : NULL, buf);
}

void msg_cb(rd_kafka_t *rk,
            const rd_kafka_message_t *
            rkmessage,
            void *opaque) {
    printf("del: %s: offset %"PRId64"\n",
           rd_kafka_err2str(rkmessage->err), rkmessage->offset);
    if(rkmessage->err)
        fprintf(stderr, "%% Message delivery failed: %s\n",
                rd_kafka_message_errstr(rkmessage));
    else
        fprintf(stderr,
                "%% Message delivered (%zd bytes, offset %"PRId64", "
                        "partition %"PRId32"): %.*s\n",
                rkmessage->len, rkmessage->offset,
                rkmessage->partition, rkmessage->len, (const char *) rkmessage->payload);
}

void msg_consume(rd_kafka_message_t* rkmessage, void * opaque) {
    if(rkmessage->err) {
        if(rkmessage-> err == RD_KAFKA_RESP_ERR__PARTITION_EOF)
            fprintf(stderr,
                    "%% Consumer reached end of %s [%"PRId32"] "
                            "message queue at offset %"PRId64"\n",
                    rd_kafka_topic_name(rkmessage->rkt),
                    rkmessage->partition, rkmessage->offset);
        else
            fprintf(stderr, "%% Consume error for topic \"%s\" [%"PRId32"] "
                            "offset %"PRId64": %s\n",
                    rd_kafka_topic_name(rkmessage->rkt),
                    rkmessage->partition,
                    rkmessage->offset,
                    rd_kafka_message_errstr(rkmessage));
    } else {
        rd_kafka_timestamp_type_t tstype;
        int64_t timestamp;
        fprintf(stdout, "%% Message (offset %"PRId64", %zd bytes):\n",
                rkmessage->offset, rkmessage->len);
        timestamp = rd_kafka_message_timestamp(rkmessage, &tstype);
        if(tstype != RD_KAFKA_TIMESTAMP_NOT_AVAILABLE) {
            const char* tsname = "?";
            if(tstype == RD_KAFKA_TIMESTAMP_CREATE_TIME)
                tsname = "create time";
            else if(tstype == RD_KAFKA_TIMESTAMP_LOG_APPEND_TIME)
                tsname = "log append time";
            fprintf(stdout, "%%Message timestamp: %s %"PRId64" "
                            "(%ds ago)\n",
                    tsname, timestamp,
                    !timestamp ? 0 :
                    (int) time(NULL) - (int)(timestamp / 1000));
        }
        if(rkmessage->key_len) {
            printf("Key: %.*s\n",
                   (int) rkmessage->key_len, (char *)rkmessage->key);
        }
        printf("%.*s\n",
               (int)rkmessage->len, (char *)rkmessage->payload);
    }
}

void metadata_print(const char* topic, const struct rd_kafka_metadata* metadata) {
    int i, j, k;
    printf("Metadata for %s (from broker %"PRId32": %s):\n",
           topic ? topic : "all topics",
           metadata->orig_broker_id,
           metadata->orig_broker_name);
    printf(" %i brokers:\n", metadata->broker_cnt);
    for(i = 0; i < metadata->broker_cnt; i++)
        printf("  broker %"PRId32" at %s:%i\n",
               metadata->brokers[i].id,
               metadata->brokers[i].host,
               metadata->brokers[i].port);
    printf("  %i topics:\n", metadata->topic_cnt);
    for(i = 0; i < metadata->topic_cnt; i++) {
        rd_kafka_metadata_topic_t* tic = &metadata->topics[i]; // pointer not topic struct
        printf("   topic \"%s\" with %i partitions:",
               tic->topic,
               tic->partition_cnt);
        if(tic->err) {
            printf(" %s", rd_kafka_err2str(tic->err));
            if(tic->err == RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE)
                printf(" (leader not available, try again)");
        }
        printf("\n");
        for(j = 0; j < tic->partition_cnt; j++) {
            rd_kafka_metadata_partition_t* part;
            part = &tic->partitions[j];
            printf("    partition %"PRId32", "
                           "leader %"PRId32", replicas: ",
                   part->id, part->leader);
            for(k = 0; k < part->replica_cnt; k++)
                printf("%s%"PRId32, k > 0 ? "," : "", part->replicas[k]);
            printf(", isrs: ");
            for(k = 0; k < part->isr_cnt; k++)
                printf("%s%"PRId32, k > 0 ? "," : "", part->isrs[k]);
            if(part->err)
                printf(", %s\n", rd_kafka_err2str(part->err));
            else
                printf("\n");
        }
    }
}

void produce_sample() {
    char* brokers = "localhost:9092";
    char* topic = "libt";
    int partition = RD_KAFKA_PARTITION_UA;
    char errstr[1024] = {'\0'};

    /* rk conf */
    rd_kafka_conf_t* rk_conf = rd_kafka_conf_new();
    rd_kafka_conf_set_log_cb(rk_conf, logger);
    rd_kafka_conf_set_dr_msg_cb(rk_conf, msg_cb);
    rd_kafka_conf_set(rk_conf, "compression.codec", "snappy", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "batch.num.messages", "10000", errstr, sizeof(errstr));

    rd_kafka_conf_set(rk_conf, "security.protocol", "SASL_PLAINTEXT", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.service.name", "your_service_name", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.keytab", "keytab", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.principal", "your_username", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.principal.password", "your_password", errstr, sizeof(errstr));

    /* rkt conf */
    rd_kafka_topic_conf_t* rkt_conf = rd_kafka_topic_conf_new();
    rd_kafka_topic_conf_set(rkt_conf, "produce.offset.report", "true", errstr, sizeof(errstr));

    /* instance(rk and rkt) handler */
    rd_kafka_t* rk = rd_kafka_new(RD_KAFKA_PRODUCER, rk_conf, errstr, sizeof(errstr));
    if(rk == NULL) {
        fprintf(stderr,
                "%% Failed to create new producer: %s\n",
                errstr);
        exit(1);
    }
    if(rd_kafka_brokers_add(rk, brokers) == 0) {
        fprintf(stderr,
                "%% No valid brokers specified\n");

    }
    rd_kafka_topic_t* rkt = rd_kafka_topic_new(rk, topic, rkt_conf);
    rkt_conf = NULL;

    /* produce */
    int sencnt = 0;
    for(int i = 0; i < 10; i++) {
        char val[512] = {'\0'};
        sprintf(val, "steam_%d", i);
        if(rd_kafka_produce(rkt, partition, RD_KAFKA_MSG_F_COPY,
                            val, strlen(val), NULL, 0, NULL) == -1)
            fprintf(stderr,
                    "%% Failed to produce to topic %s "
                            "partition %i: %s\n",
                    rd_kafka_topic_name(rkt), partition,
                    rd_kafka_err2str(rd_kafka_last_error()));
        else
            sencnt++;
        rd_kafka_poll(rk, 0);
        sleep(1);
    }
    rd_kafka_poll(rk, 0);

    /* clear */
    while (rd_kafka_outq_len(rk) > 0)
        rd_kafka_poll(rk, 100);
    rd_kafka_topic_destroy(rkt);
    rd_kafka_destroy(rk);
    while(rd_kafka_wait_destroyed(1000) == -1)
        printf("waiting for librdkafka to terminate\n");
}

void consume_sample() {
    char* brokers = "localhost:9092";
    char* topic = "libt";
    int partition = 0;
    char errstr[1024] = {'\0'};

    /* rk conf */
    rd_kafka_conf_t* rk_conf = rd_kafka_conf_new();
    rd_kafka_conf_set_log_cb(rk_conf, logger);
    rd_kafka_conf_set(rk_conf, "security.protocol", "SASL_PLAINTEXT", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.service.name", "your_service_name", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.keytab", "keytab", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.principal", "your_username", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.principal.password", "your_password", errstr, sizeof(errstr));

    /* rkt conf */
    rd_kafka_topic_conf_t* rkt_conf = rd_kafka_topic_conf_new();

    /* instance */
    rd_kafka_t* rk = rd_kafka_new(RD_KAFKA_CONSUMER, rk_conf, errstr, sizeof(errstr));
    if(rk == NULL) {
        fprintf(stderr,
                "%% failed to create new consumer: %s\n",
                errstr);
        exit(1);
    }
    if(rd_kafka_brokers_add(rk, brokers) == 0) {
        fprintf(stderr, "%% No valid brokers specified\n");
        exit(1);
    }
    int64_t lo, hi;
    rd_kafka_resp_err_t err;
    if((err = rd_kafka_query_watermark_offsets(rk, topic, partition, &lo, &hi, 5000)) != RD_KAFKA_RESP_ERR_NO_ERROR) {
        fprintf(stderr, "%% query_watermark_offsets() "
                        "failed: %s\n",
                rd_kafka_err2str(err));
        exit(1);
    } else
        printf("%s [%d]: low - high offsets: "
                       "%"PRId64" - %"PRId64"\n",
               topic, partition, lo, hi);
    rd_kafka_topic_t* rkt = rd_kafka_topic_new(rk, topic, rkt_conf);
    rkt_conf = NULL;

    /* consume */
    if(rd_kafka_consume_start(rkt, partition, hi - 10) == -1) {
        rd_kafka_resp_err_t err = rd_kafka_last_error();
        fprintf(stderr, "%% Failed to start comsuming: %s\n",
                rd_kafka_err2str(err));
        if(err == RD_KAFKA_RESP_ERR__INVALID_ARG)
            fprintf(stderr,
                    "%% Broker based offset storage "
                            "requires a group.id, "
                            "add: -X group.id=yourGroup\n");
        exit(1);
    } else {
        int64_t offset = 0;
        for(int i = 0; i < 10; i++) {
            rd_kafka_message_t* rkmessage = NULL;
            rd_kafka_poll(rk, 0);
            rkmessage = rd_kafka_consume(rkt, partition, 1000);
            if(!rkmessage)
                continue;
            offset = rkmessage->offset;
            msg_consume(rkmessage, NULL);
            rd_kafka_message_destroy(rkmessage);
        }
    }

    /* clear */
    rd_kafka_consume_stop(rkt, partition);
    while (rd_kafka_outq_len(rk) > 0)
        rd_kafka_poll(rk, 100);
    rd_kafka_topic_destroy(rkt);
    rd_kafka_destroy(rk);
    while(rd_kafka_wait_destroyed(1000) == -1)
        printf("waiting for librdkafka to terminate\n");
}

void metadata_sample() {
    char* brokers = "localhost:9092";
    char* topic = "libt";
    int partition = 0;
    int retry = 3;
    char errstr[1024] = {'\0'};
    rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;

    /* rk conf */
    rd_kafka_conf_t* rk_conf = rd_kafka_conf_new();
    rd_kafka_conf_set_log_cb(rk_conf, logger);
    rd_kafka_conf_set(rk_conf, "security.protocol", "SASL_PLAINTEXT", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.service.name", "your_service_name", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.keytab", "keytab", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.principal", "your_username", errstr, sizeof(errstr));
    rd_kafka_conf_set(rk_conf, "sasl.kerberos.principal.password", "your_password", errstr, sizeof(errstr));

    /* rkt conf */
    rd_kafka_topic_conf_t* rkt_conf = rd_kafka_topic_conf_new();

    /* instance */
    rd_kafka_t* rk = rd_kafka_new(RD_KAFKA_PRODUCER, rk_conf, errstr, sizeof(errstr));
    if(rk == NULL) {
        fprintf(stderr, "%% Failed to create new producer: %s\n", errstr);
        exit(1);
    }
    if(rd_kafka_brokers_add(rk, brokers) == 0) {
        fprintf(stderr, "%% No valid brokers specified\n");
        exit(1);
    }
    rd_kafka_topic_t* rkt = NULL;
    if(topic) {
        rkt = rd_kafka_topic_new(rk, topic, rkt_conf);
        rkt_conf = NULL;
    }

    /* metadata */
    int cnt = 0;
    while (cnt++ < retry) {
        const struct rd_kafka_metadata* metadata;
        err = rd_kafka_metadata(rk, rkt ? 0 : 1, rkt, &metadata, 5000); // return change the metadata pointer value
        if(err != RD_KAFKA_RESP_ERR_NO_ERROR) {
            fprintf(stderr,
                    "%% Failed to acquire metadata: %s\n",
                    rd_kafka_err2str(err));
            continue;
        } else {
            metadata_print(topic, metadata);
            rd_kafka_metadata_destroy(metadata);
            break;
        }
    }

    /* clear */
    if(rkt)
        rd_kafka_topic_destroy(rkt);
    rd_kafka_destroy(rk);
    while(rd_kafka_wait_destroyed(1000) == -1)
        printf("waiting for librdkafka to terminate\n");
}

int main(int argc, char ** argv, char ** envp) {
    produce_sample();
    consume_sample();
    metadata_sample();
    return 0;
}