/**
 * HGS Manipulation Framework - Main Header
 * 
 * A comprehensive C framework for testing Hyper-V Host Guardian Service (HGS) 
 * security mechanisms and Shielded VM infrastructure.
 * 
 * Author: HGS-Analyzer contributors
 * Version: 1.0.0
 */

#ifndef HGS_MANIPULATOR_H
#define HGS_MANIPULATOR_H

#include <windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <wbemcli.h>
#include <rpc.h>
#include <rpcndr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// Framework version
#define HGS_FRAMEWORK_VERSION "1.0.0"
#define HGS_FRAMEWORK_BUILD __DATE__ " " __TIME__

// Error codes
#define HGS_SUCCESS 0
#define HGS_ERROR_INVALID_PARAM -1
#define HGS_ERROR_MEMORY_ALLOC -2
#define HGS_ERROR_API_CALL -3
#define HGS_ERROR_RPC_OBSERVE -4
#define HGS_ERROR_ATTESTATION -5
#define HGS_ERROR_KEY_PROTECTOR -6
#define HGS_ERROR_VM_POLICY -7
#define HGS_ERROR_CLEANUP -8

// HGS Configuration
#define HGS_DEFAULT_ENDPOINT "localhost"
#define HGS_DEFAULT_PORT 443
#define HGS_RPC_VERSION 1
#define HGS_MAX_VM_NAME_LEN 256
#define HGS_MAX_ATTESTATION_DATA_LEN 4096

// RPC Message Types
#define HGS_MSG_ATTESTATION_REQUEST 0x01
#define HGS_MSG_ATTESTATION_RESPONSE 0x02
#define HGS_MSG_KEY_REQUEST 0x10
#define HGS_MSG_KEY_RESPONSE 0x11
#define HGS_MSG_POLICY_UPDATE 0x20

// Attestation Modes
typedef enum {
    HGS_ATTESTATION_TPM = 1,
    HGS_ATTESTATION_ADMIN = 2,
    HGS_ATTESTATION_CUSTOM = 3
} hgs_attestation_mode_t;

// Analysis Modes
typedef enum {
    HGS_ANALYSIS_FULL = 1,
    HGS_ANALYSIS_ATTESTATION_ONLY = 2,
    HGS_ANALYSIS_KEY_ONLY = 3,
    HGS_ANALYSIS_POLICY_ONLY = 4
} hgs_analysis_mode_t;

// RPC Packet Structure
typedef struct {
    uint32_t version;
    uint32_t message_type;
    uint32_t sequence_number;
    uint32_t payload_length;
    uint8_t* payload;
    uint8_t checksum[16];
} hgs_rpc_packet_t;

// Attestation Data Structure
typedef struct {
    hgs_attestation_mode_t mode;
    uint8_t* tpm_data;
    size_t tpm_data_len;
    uint8_t* certificates;
    size_t certificates_len;
    uint8_t* signatures;
    size_t signatures_len;
    uint64_t timestamp;
} hgs_attestation_data_t;

// VM Information Structure
typedef struct {
    char name[HGS_MAX_VM_NAME_LEN];
    char id[64];
    bool is_shielded;
    bool is_running;
    uint32_t state;
} hgs_vm_info_t;

// Key Protector Structure
typedef struct {
    uint8_t* key_data;
    size_t key_data_len;
    uint8_t* protector_data;
    size_t protector_data_len;
    uint32_t algorithm_id;
    uint64_t creation_time;
} hgs_key_protector_t;

// Framework Configuration
typedef struct {
    char hgs_endpoint[256];
    uint16_t hgs_port;
    hgs_attestation_mode_t attestation_mode;
    bool verbose_logging;
    bool debug_mode;
    char log_file[256];
} hgs_config_t;

// Main Framework Structure
typedef struct {
    hgs_config_t config;
    HANDLE log_file;
    bool initialized;
    bool observing;
    HANDLE observe_thread;
    CRITICAL_SECTION packet_queue_cs;
    LIST_ENTRY packet_queue;
} hgs_framework_t;

// Function Declarations

// Core Framework Functions
int hgs_framework_init(hgs_framework_t* framework, const hgs_config_t* config);
int hgs_framework_cleanup(hgs_framework_t* framework);
int hgs_framework_run_analysis(hgs_framework_t* framework, const char* target_vm, hgs_analysis_mode_t mode);

// RPC Observer Functions
int hgs_rpc_observer_init(hgs_framework_t* framework);
int hgs_rpc_observer_start(hgs_framework_t* framework);
int hgs_rpc_observer_stop(hgs_framework_t* framework);
int hgs_rpc_observer_cleanup(hgs_framework_t* framework);
int hgs_synthesize_fake_attestation(hgs_framework_t* framework, const hgs_attestation_data_t* attestation);
int hgs_list_vms(hgs_framework_t* framework, hgs_vm_info_t** vms, size_t* vm_count);

// Attestation Fuzzer Functions
int hgs_attestation_fuzzer_init(hgs_framework_t* framework);
int hgs_generate_fake_attestation(hgs_framework_t* framework, hgs_attestation_data_t* attestation);
int hgs_fuzz_tpm_data(hgs_framework_t* framework, uint8_t** tpm_data, size_t* tpm_data_len);
int hgs_model_certificates(hgs_framework_t* framework, uint8_t** cert_data, size_t* cert_data_len);
int hgs_attestation_fuzzer_cleanup(hgs_framework_t* framework);

// Key Protector Model Functions
int hgs_key_protector_model_init(hgs_framework_t* framework);
int hgs_model_key_protector(hgs_framework_t* framework, const char* vm_name, hgs_key_protector_t* protector);
int hgs_extract_vm_keys(hgs_framework_t* framework, const char* vm_name, hgs_key_protector_t* protector);
int hgs_synthesize_key_protector(hgs_framework_t* framework, const char* vm_name, const hgs_key_protector_t* protector);
int hgs_key_protector_model_cleanup(hgs_framework_t* framework);

// VM Policy Sampler Functions
int hgs_vm_policy_sampler_init(hgs_framework_t* framework);
int hgs_synthesize_vm_policy(hgs_framework_t* framework, const char* vm_name, const char* policy_data);
int hgs_modify_vm_security_settings(hgs_framework_t* framework, const char* vm_name);
int hgs_disable_vm_shielding(hgs_framework_t* framework, const char* vm_name);
int hgs_vm_policy_sampler_cleanup(hgs_framework_t* framework);

// Utility Functions
// `message` is a printf-style format string; the variadic args are the
// format arguments (the HGS_*_LOG macros forward them via __VA_ARGS__).
// The declaration must stay variadic to match the implementation.
int hgs_log_message(hgs_framework_t* framework, const char* level, const char* message, ...);
int hgs_allocate_memory(void** ptr, size_t size);
int hgs_free_memory(void* ptr);
int hgs_parse_config_file(const char* config_path, hgs_config_t* config);
int hgs_validate_vm_name(const char* vm_name);
int hgs_calculate_checksum(const uint8_t* data, size_t data_len, uint8_t* checksum);

// Windows API Helper Functions
int hgs_get_tpm_info(uint8_t** tpm_data, size_t* tpm_data_len);
int hgs_get_system_certificates(uint8_t** cert_data, size_t* cert_data_len);
int hgs_enumerate_hyperv_vms(hgs_vm_info_t** vms, size_t* vm_count);
int hgs_hook_rpc_functions(void);
int hgs_unhook_rpc_functions(void);

// Debug and Logging Functions
#ifdef DEBUG
#define HGS_DEBUG_LOG(framework, format, ...) \
    hgs_log_message(framework, "DEBUG", format, ##__VA_ARGS__)
#else
#define HGS_DEBUG_LOG(framework, format, ...)
#endif

#define HGS_INFO_LOG(framework, format, ...) \
    hgs_log_message(framework, "INFO", format, ##__VA_ARGS__)

#define HGS_WARN_LOG(framework, format, ...) \
    hgs_log_message(framework, "WARN", format, ##__VA_ARGS__)

#define HGS_ERROR_LOG(framework, format, ...) \
    hgs_log_message(framework, "ERROR", format, ##__VA_ARGS__)

#endif // HGS_MANIPULATOR_H
