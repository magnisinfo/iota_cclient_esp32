#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "client_api.h"

#include "freertos/FreeRTOS.h"
#include "linenoise/linenoise.h"
#include "esp_task_wdt.h"

static const char *TAG = "cclient";
static const tryte_t TAG_TRYTES[] = "ENTANGLEDCCLIENT99999999999";    
static const int SECURITY_LEVEL = 2;
static const int DEPTH = 3;
static const int MWM = 14;

char* walletSeed = NULL;
flex_trit_t walletSeedTrits[HASH_LENGTH_TRIT];

static void consoleRead(char* prompt, char** line){    
    while(true){        
        esp_task_wdt_reset();
        if(*line != NULL) free(*line);
        char *newLine = linenoise(prompt);
        if(newLine == NULL)
            continue;
        else
        {
            *line = newLine;
            break;
        }
    }
}

retcode_t start_iota_client(iota_client_service_t *const service)
{    
	init_iota_client(service);
    
    char* prompt = ">";
    printf("Welcome to IOTA wallet. Write you seed:\n");
    char* line = NULL;
    while(true){
        consoleRead(prompt, &line);
        if(strlen(line) == HASH_LENGTH_TRYTE){
            walletSeed = malloc(strlen(line)+1);
            memcpy(walletSeed, line, strlen(line)+1);
            flex_trits_from_trytes(walletSeedTrits, HASH_LENGTH_TRIT, (tryte_t*)walletSeed, HASH_LENGTH_TRYTE, HASH_LENGTH_TRYTE);
            break;
        }else
            printf("Incorrect seed! Enter again:\n");
    }            
    
    while(true){
        printf("\nChoose operation:\n");
        printf("(1)-Get account balance\n");
        printf("(2)-Send tokens to address\n");
        printf("(3)-Send message\n");
        consoleRead(prompt, &line);
        int choosedMenu = atoi(line);

        if(choosedMenu == 1){
            printf("Getting wallet balance...\n");            
            if(show_account_info(service) != RC_OK)
                printf("Can't get account balance! Try again.\n");            
        }else if(choosedMenu == 2 || choosedMenu == 3){
            printf("Enter destination address:\n");
            consoleRead(prompt, &line);
            if(strlen(line) != HASH_LENGTH_TRYTE)
            {
                printf("Incorrect address!\n");
                continue;
            }
            char* addressToSend = malloc(strlen(line)+1);
            memcpy(addressToSend, line, strlen(line)+1);
            
            int tokensAmount = 0;
            char* message = "";
            if(choosedMenu == 2){
              printf("How many tokens send?:\n");
              consoleRead(prompt, &line);
              tokensAmount = atoi(line);
              message = "Value transfer!";

              printf("Sending tokens to %s...\n", addressToSend);
            }else{
              printf("Enter your message:\n");
              consoleRead(prompt, &line);              
              message = line;

              printf("Sending message to %s...\n", addressToSend);
            }
            
            if(send_transfer(service, addressToSend, tokensAmount, message) != RC_OK)
                printf("Can't send trasfer! Try again.\n");
            else
                printf("Successfully sended!\n");            
        }else{
            printf("Unknown operation!\n");
        }
    }
    	
    return 0;
}

void init_iota_client(iota_client_service_t *const service)
{
  service->http.path = "/";
  service->http.content_type = "application/json";
  service->http.accept = "application/json";
  service->http.host = CONFIG_IRI_NODE_URI;
  service->http.port = atoi(CONFIG_IRI_NODE_PORT);
  service->http.api_version = 1;
#ifdef CONFIG_ENABLE_HTTPS
  service->http.ca_pem = amazon_ca1_pem;
#else
  service->http.ca_pem = NULL;
#endif
  service->serializer_type = SR_JSON;
  logger_init();
  logger_output_register(stdout);
  logger_output_level_set(stdout, LOGGER_DEBUG);
  iota_client_core_init(service);
  iota_client_extended_init();
}

retcode_t show_node_info(iota_client_service_t *const service)
{
  retcode_t ret = RC_ERROR;
  // test get_node_info
  trit_t trytes_out[NUM_TRYTES_HASH + 1];
  size_t trits_count = 0;
  get_node_info_res_t *node_res = get_node_info_res_new();
  if (!node_res)
  {
    return RC_OOM;
  }

  ret = iota_client_get_node_info(service, node_res);
  if (ret == RC_OK)
  {
    printf("appName %s \n", node_res->app_name->data);
    printf("appVersion %s \n", node_res->app_version->data);
    trits_count = flex_trits_to_trytes(trytes_out, NUM_TRYTES_HASH,
                                       node_res->latest_milestone, NUM_TRITS_HASH,
                                       NUM_TRITS_HASH);
    if (trits_count == 0)
    {
      printf("trit converting failed\n");
      goto done;
    }
    trytes_out[NUM_TRYTES_HASH] = '\0';
    printf("latestMilestone %s \n", trytes_out);
    printf("latestMilestoneIndex %zu\n", (uint32_t)node_res->latest_milestone_index);
    trits_count = flex_trits_to_trytes(trytes_out, NUM_TRYTES_HASH,
                                       node_res->latest_milestone, NUM_TRITS_HASH,
                                       NUM_TRITS_HASH);
    if (trits_count == 0)
    {
      printf("trit converting failed\n");
      goto done;
    }
    trytes_out[NUM_TRYTES_HASH] = '\0';
    printf("latestSolidSubtangleMilestone %s \n", trytes_out);

    printf("latestSolidSubtangleMilestoneIndex %zu\n",
           node_res->latest_solid_subtangle_milestone_index);
    printf("milestoneStratIndex %zu\n", node_res->milestone_start_index);
    printf("neighbors %d \n", node_res->neighbors);
    printf("packetsQueueSize %d \n", node_res->packets_queue_size);
    printf("time %" PRIu64 "\n", node_res->time);
    printf("tips %zu \n", node_res->tips);
    printf("transactionsToRequest %zu\n", node_res->transactions_to_request);
  }
  else
  {
    ESP_LOGE(TAG, "get_node_info error:%s", error_2_string(ret));
  }

done:
  get_node_info_res_free(&node_res);
  return ret;
}

retcode_t send_transfer(iota_client_service_t *const service, char* addressToSend, int tokensAmount, char* message){    
    retcode_t ret = RC_ERROR;    
    
    flex_trit_t tagTrits[(sizeof(TAG_TRYTES)-1)*3];
    flex_trits_from_trytes(tagTrits, sizeof(tagTrits), TAG_TRYTES, sizeof(TAG_TRYTES)-1, sizeof(TAG_TRYTES)-1);
    
    flex_trit_t addrTritsTo[NUM_TRITS_HASH];
    flex_trits_from_trytes(addrTritsTo, NUM_TRITS_HASH, (tryte_t*)addressToSend, NUM_TRYTES_HASH, NUM_TRYTES_HASH);
    
    transfer_t trIn;
    trIn.value = tokensAmount;
    memcpy(trIn.address, addrTritsTo, FLEX_TRIT_SIZE_243);
    memcpy(trIn.tag, tagTrits, sizeof(tagTrits));
    transfer_message_set_string(&trIn, message);

    transfer_array_t* trs = transfer_array_new();
    transfer_array_add(trs, &trIn);
    
    bundle_transactions_t *out_txs = NULL;
    bundle_transactions_new(&out_txs);
        
    ret = iota_client_send_transfer(service, walletSeedTrits, SECURITY_LEVEL, DEPTH, MWM, false, trs, NULL, NULL, NULL, out_txs);
    transfer_array_free(trs);

    if(ret != RC_OK)
        printf("Resp: %s\n", error_2_string(ret));
    
    return ret;
}

retcode_t show_account_info(iota_client_service_t *const service)
{
    const int SECURITY_LEVEL = 2;

    retcode_t ret = RC_ERROR;

    flex_trit_t seedTrits[HASH_LENGTH_TRIT];
    flex_trits_from_trytes(seedTrits, HASH_LENGTH_TRIT, (tryte_t*)walletSeed, HASH_LENGTH_TRYTE, HASH_LENGTH_TRYTE);
    
    account_data_t* out_account = (account_data_t*)malloc(sizeof(account_data_t));
    account_data_init(out_account);
    
    ret = iota_client_get_account_data(service, seedTrits, SECURITY_LEVEL, out_account);
    if(ret != RC_OK){
        printf("Resp: %s\n", error_2_string(ret));
        return ret;
    }
    
    printf("Total balance: %"PRIu64"\n", out_account->balance);    
    for(int i = 0; i < utarray_len(out_account->balances); i++){        
        flex_trit_t* addrTrits = hash243_queue_at(out_account->addresses, i);
        tryte_t addrTrytes[HASH_LENGTH_TRYTE+1];
        flex_trits_to_trytes(addrTrytes, HASH_LENGTH_TRYTE, addrTrits, HASH_LENGTH_TRIT, HASH_LENGTH_TRIT);
        addrTrytes[HASH_LENGTH_TRYTE] = '\0';        
        printf("Address(%d) - %s, balance: %"PRIu64"\n", i, addrTrytes, *(uint64_t*)utarray_eltptr(out_account->balances, i));        
    }        
    
    flex_trit_t* addrTrits = out_account->latest_address;
    tryte_t addrTrytes[HASH_LENGTH_TRYTE+1];
    flex_trits_to_trytes(addrTrytes, HASH_LENGTH_TRYTE, addrTrits, HASH_LENGTH_TRIT, HASH_LENGTH_TRIT);
    addrTrytes[HASH_LENGTH_TRYTE] = '\0';    
    printf("Not used address - %s\n", addrTrytes);
    
    account_data_clear(out_account);

    return ret;
}