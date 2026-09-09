/**
 * HGS Manipulation Framework - Core Framework Implementation
 * 
 * Main framework functions for orchestrating HGS manipulation components.
 */

#include "hgs_manipulator.h"
#include <time.h>

int hgs_framework_init(hgs_framework_t* framework, const hgs_config_t* config)
{
    if (!framework || !config) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    // Initialize framework structure
    memset(framework, 0, sizeof(hgs_framework_t));
    framework->config = *config;
    framework->initialized = false;
    framework->observing = false;
    framework->observe_thread = NULL;
    
    // Initialize critical section for packet queue
    if (!InitializeCriticalSectionAndSpinCount(&framework->packet_queue_cs, 4000)) {
        HGS_ERROR_LOG(framework, "Failed to initialize critical section");
        return HGS_ERROR_API_CALL;
    }
    
    // Initialize packet queue
    InitializeListHead(&framework->packet_queue);
    
    // Open log file
    if (config->log_file[0] != '\0') {
        framework->log_file = CreateFileA(
            config->log_file,
            GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (framework->log_file == INVALID_HANDLE_VALUE) {
            HGS_ERROR_LOG(framework, "Failed to open log file: %s", config->log_file);
            // Continue without logging to file
            framework->log_file = NULL;
        }
    }
    
    // Initialize components
    int result = hgs_rpc_observer_init(framework);
    if (result != HGS_SUCCESS) {
        HGS_ERROR_LOG(framework, "Failed to initialize RPC observer: %d", result);
        return result;
    }
    
    result = hgs_attestation_fuzzer_init(framework);
    if (result != HGS_SUCCESS) {
        HGS_ERROR_LOG(framework, "Failed to initialize attestation fuzzer: %d", result);
        hgs_rpc_observer_cleanup(framework);
        return result;
    }
    
    result = hgs_key_protector_model_init(framework);
    if (result != HGS_SUCCESS) {
        HGS_ERROR_LOG(framework, "Failed to initialize key protector model: %d", result);
        hgs_attestation_fuzzer_cleanup(framework);
        hgs_rpc_observer_cleanup(framework);
        return result;
    }
    
    result = hgs_vm_policy_sampler_init(framework);
    if (result != HGS_SUCCESS) {
        HGS_ERROR_LOG(framework, "Failed to initialize VM policy sampler: %d", result);
        hgs_key_protector_model_cleanup(framework);
        hgs_attestation_fuzzer_cleanup(framework);
        hgs_rpc_observer_cleanup(framework);
        return result;
    }
    
    framework->initialized = true;
    HGS_INFO_LOG(framework, "HGS Manipulation Framework initialized successfully");
    
    return HGS_SUCCESS;
}

int hgs_framework_cleanup(hgs_framework_t* framework)
{
    if (!framework) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    HGS_INFO_LOG(framework, "Cleaning up HGS Manipulation Framework...");
    
    // Cleanup components in reverse order
    hgs_vm_policy_sampler_cleanup(framework);
    hgs_key_protector_model_cleanup(framework);
    hgs_attestation_fuzzer_cleanup(framework);
    hgs_rpc_observer_cleanup(framework);
    
    // Cleanup critical section
    DeleteCriticalSection(&framework->packet_queue_cs);
    
    // Close log file
    if (framework->log_file && framework->log_file != INVALID_HANDLE_VALUE) {
        CloseHandle(framework->log_file);
        framework->log_file = NULL;
    }
    
    framework->initialized = false;
    HGS_INFO_LOG(framework, "HGS Manipulation Framework cleanup completed");
    
    return HGS_SUCCESS;
}

int hgs_framework_run_analysis(hgs_framework_t* framework, const char* target_vm, hgs_analysis_mode_t mode)
{
    if (!framework || !target_vm || !framework->initialized) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    HGS_INFO_LOG(framework, "Starting HGS analysis chain against VM: %s", target_vm);
    HGS_INFO_LOG(framework, "Analysis mode: %d", mode);
    
    int result = HGS_SUCCESS;
    
    // Step 1: Start RPC observation
    if (mode == HGS_ANALYSIS_FULL || mode == HGS_ANALYSIS_ATTESTATION_ONLY) {
        HGS_INFO_LOG(framework, "Step 1: Starting HGS RPC observation...");
        result = hgs_rpc_observer_start(framework);
        if (result != HGS_SUCCESS) {
            HGS_ERROR_LOG(framework, "Failed to start RPC observation: %d", result);
            return result;
        }
        
        // Wait a moment for observation to establish
        Sleep(1000);
    }
    
    // Step 2: Generate and sample fake attestation
    if (mode == HGS_ANALYSIS_FULL || mode == HGS_ANALYSIS_ATTESTATION_ONLY) {
        HGS_INFO_LOG(framework, "Step 2: Generating and sampling fake attestation...");
        
        hgs_attestation_data_t attestation = {0};
        result = hgs_generate_fake_attestation(framework, &attestation);
        if (result != HGS_SUCCESS) {
            HGS_ERROR_LOG(framework, "Failed to generate fake attestation: %d", result);
            hgs_rpc_observer_stop(framework);
            return result;
        }
        
        result = hgs_synthesize_fake_attestation(framework, &attestation);
        if (result != HGS_SUCCESS) {
            HGS_ERROR_LOG(framework, "Failed to sample fake attestation: %d", result);
            hgs_rpc_observer_stop(framework);
            return result;
        }
        
        // Cleanup attestation data
        hgs_free_memory(attestation.tpm_data);
        hgs_free_memory(attestation.certificates);
        hgs_free_memory(attestation.signatures);
    }
    
    // Step 3: Model key protector
    if (mode == HGS_ANALYSIS_FULL || mode == HGS_ANALYSIS_KEY_ONLY) {
        HGS_INFO_LOG(framework, "Step 3: Modeling key protector...");
        
        hgs_key_protector_t protector = {0};
        result = hgs_model_key_protector(framework, target_vm, &protector);
        if (result != HGS_SUCCESS) {
            HGS_ERROR_LOG(framework, "Failed to model key protector: %d", result);
            hgs_rpc_observer_stop(framework);
            return result;
        }
        
        // Cleanup protector data
        hgs_free_memory(protector.key_data);
        hgs_free_memory(protector.protector_data);
    }
    
    // Step 4: Sample VM policy modifications
    if (mode == HGS_ANALYSIS_FULL || mode == HGS_ANALYSIS_POLICY_ONLY) {
        HGS_INFO_LOG(framework, "Step 4: Sampleing VM policy modifications...");
        
        result = hgs_modify_vm_security_settings(framework, target_vm);
        if (result != HGS_SUCCESS) {
            HGS_ERROR_LOG(framework, "Failed to modify VM security settings: %d", result);
            hgs_rpc_observer_stop(framework);
            return result;
        }
    }
    
    // Stop RPC observation
    if (mode == HGS_ANALYSIS_FULL || mode == HGS_ANALYSIS_ATTESTATION_ONLY) {
        hgs_rpc_observer_stop(framework);
    }
    
    HGS_INFO_LOG(framework, "HGS analysis chain completed successfully!");
    return HGS_SUCCESS;
}

int hgs_log_message(hgs_framework_t* framework, const char* level, const char* message, ...)
{
    if (!framework || !level || !message) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    // Get current time
    time_t now;
    time(&now);
    struct tm* timeinfo = localtime(&now);
    
    // Format timestamp
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    // Format log message
    char log_buffer[1024];
    va_list args;
    va_start(args, message);
    vsnprintf(log_buffer, sizeof(log_buffer), message, args);
    va_end(args);
    
    // Create full log line
    char full_log[2048];
    snprintf(full_log, sizeof(full_log), "[%s] [%s] %s\n", timestamp, level, log_buffer);
    
    // Output to console
    printf("%s", full_log);
    
    // Output to log file if available
    if (framework->log_file && framework->log_file != INVALID_HANDLE_VALUE) {
        DWORD bytes_written;
        WriteFile(framework->log_file, full_log, (DWORD)strlen(full_log), &bytes_written, NULL);
    }
    
    return HGS_SUCCESS;
}

int hgs_allocate_memory(void** ptr, size_t size)
{
    if (!ptr || size == 0) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    *ptr = malloc(size);
    if (!*ptr) {
        return HGS_ERROR_MEMORY_ALLOC;
    }
    
    memset(*ptr, 0, size);
    return HGS_SUCCESS;
}

int hgs_free_memory(void* ptr)
{
    if (ptr) {
        free(ptr);
    }
    return HGS_SUCCESS;
}

/*
 * Minimal JSON value extractor.
 *
 * Looks for `"key": value` or `"key" : value` patterns in a buffer and
 * copies the value (string or number) into `out` (null-terminated).
 * Returns 1 on success, 0 if the key was not found.
 *
 * String values: strips surrounding quotes.
 * Number / boolean values: copies the raw token.
 */
static int json_extract(const char* buf, const char* key,
                         char* out, size_t out_sz)
{
    char   search[128];
    const char* p;
    const char* v;
    size_t i = 0;

    if (!buf || !key || !out || !out_sz) return 0;

    snprintf(search, sizeof(search), "\"%s\"", key);
    p = strstr(buf, search);
    if (!p) return 0;

    /* Skip past key and optional whitespace/colon. */
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == ' ') p++;

    if (*p == '"') {
        /* String value — copy until closing quote. */
        v = ++p;
        while (*p && *p != '"') p++;
        i = (size_t)(p - v);
        if (i >= out_sz) i = out_sz - 1;
        memcpy(out, v, i);
    } else {
        /* Number / boolean / null — copy until delimiter. */
        v = p;
        while (*p && *p != ',' && *p != '\n' && *p != '}' && *p != ' ') p++;
        i = (size_t)(p - v);
        if (i >= out_sz) i = out_sz - 1;
        memcpy(out, v, i);
    }
    out[i] = '\0';
    return (i > 0) ? 1 : 0;
}

int hgs_parse_config_file(const char* config_path, hgs_config_t* config)
{
    FILE*  f;
    char*  buf;
    long   file_size;
    size_t bytes_read;
    char   tmp[256];

    if (!config_path || !config) {
        return HGS_ERROR_INVALID_PARAM;
    }

    f = fopen(config_path, "rb");
    if (!f) {
        HGS_INFO_LOG(NULL, "Config file not found (%s), using defaults", config_path);
        return HGS_SUCCESS;
    }

    fseek(f, 0, SEEK_END);
    file_size = ftell(f);
    rewind(f);

    if (file_size <= 0 || file_size > 65536) {
        fclose(f);
        HGS_INFO_LOG(NULL, "Config file too large or empty, using defaults");
        return HGS_SUCCESS;
    }

    buf = (char*)malloc((size_t)file_size + 1);
    if (!buf) {
        fclose(f);
        return HGS_ERROR_MEMORY_ALLOC;
    }

    bytes_read = fread(buf, 1, (size_t)file_size, f);
    fclose(f);
    buf[bytes_read] = '\0';

    /* --- hgs section --- */
    if (json_extract(buf, "endpoint", tmp, sizeof(tmp)))
        strncpy(config->hgs_endpoint, tmp, sizeof(config->hgs_endpoint) - 1);

    if (json_extract(buf, "port", tmp, sizeof(tmp)))
        config->hgs_port = (uint16_t)atoi(tmp);

    if (json_extract(buf, "attestation_mode", tmp, sizeof(tmp))) {
        if (strcmp(tmp, "tpm") == 0)
            config->attestation_mode = HGS_ATTESTATION_TPM;
        else if (strcmp(tmp, "admin") == 0)
            config->attestation_mode = HGS_ATTESTATION_ADMIN;
        else
            config->attestation_mode = HGS_ATTESTATION_CUSTOM;
    }

    /* --- logging section --- */
    if (json_extract(buf, "file", tmp, sizeof(tmp)))
        strncpy(config->log_file, tmp, sizeof(config->log_file) - 1);

    if (json_extract(buf, "level", tmp, sizeof(tmp))) {
        config->verbose_logging = (strcmp(tmp, "DEBUG") == 0) ? true : false;
        config->debug_mode      = config->verbose_logging;
    }

    free(buf);
    HGS_INFO_LOG(NULL, "Config loaded from %s (endpoint=%s port=%u)",
                 config_path, config->hgs_endpoint, config->hgs_port);
    return HGS_SUCCESS;
}

int hgs_validate_vm_name(const char* vm_name)
{
    if (!vm_name) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    size_t len = strlen(vm_name);
    if (len == 0 || len >= HGS_MAX_VM_NAME_LEN) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    // Check for invalid characters
    for (size_t i = 0; i < len; i++) {
        char c = vm_name[i];
        if (c < 32 || c > 126 || c == '<' || c == '>' || c == '|' || c == '*' || c == '?') {
            return HGS_ERROR_INVALID_PARAM;
        }
    }
    
    return HGS_SUCCESS;
}

int hgs_calculate_checksum(const uint8_t* data, size_t data_len, uint8_t* checksum)
{
    if (!data || data_len == 0 || !checksum) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    // Simple MD5-like checksum for demonstration
    // In production, use proper cryptographic hash
    uint32_t hash = 0;
    for (size_t i = 0; i < data_len; i++) {
        hash = hash * 31 + data[i];
    }
    
    // Convert to 16-byte checksum
    for (int i = 0; i < 16; i++) {
        checksum[i] = (uint8_t)((hash >> (i * 2)) & 0xFF);
    }
    
    return HGS_SUCCESS;
}
