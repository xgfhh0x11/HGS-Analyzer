/**
 * HGS Manipulation Framework - Main Entry Point
 * 
 * Command-line interface for the HGS manipulation framework.
 */

#include "hgs_manipulator.h"
#include "getopt.h"   /* vendored shim in include/ — MSVC-portable */

// Global framework instance
static hgs_framework_t g_framework = {0};

// Function prototypes
static void print_usage(const char* program_name);
static void print_version(void);
static int parse_command_line(int argc, char* argv[], hgs_config_t* config, 
                             char* target_vm, hgs_analysis_mode_t* analysis_mode);
static void signal_handler(int signal);
static void cleanup_and_exit(int exit_code);

int main(int argc, char* argv[])
{
    hgs_config_t config = {0};
    char target_vm[HGS_MAX_VM_NAME_LEN] = {0};
    hgs_analysis_mode_t analysis_mode = HGS_ANALYSIS_FULL;
    int result = HGS_SUCCESS;
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Parse command line arguments
    result = parse_command_line(argc, argv, &config, target_vm, &analysis_mode);
    if (result != HGS_SUCCESS) {
        print_usage(argv[0]);
        cleanup_and_exit(1);
    }
    
    // Initialize framework
    result = hgs_framework_init(&g_framework, &config);
    if (result != HGS_SUCCESS) {
        HGS_ERROR_LOG(&g_framework, "Failed to initialize framework: %d", result);
        cleanup_and_exit(1);
    }
    
    HGS_INFO_LOG(&g_framework, "HGS Manipulation Framework v%s started", HGS_FRAMEWORK_VERSION);
    HGS_INFO_LOG(&g_framework, "Build: %s", HGS_FRAMEWORK_BUILD);
    
    // Execute analysis if target VM specified
    if (strlen(target_vm) > 0) {
        HGS_INFO_LOG(&g_framework, "Starting analysis of VM: %s", target_vm);
        HGS_INFO_LOG(&g_framework, "Analysis mode: %d", analysis_mode);
        
        result = hgs_framework_run_analysis(&g_framework, target_vm, analysis_mode);
        if (result == HGS_SUCCESS) {
            HGS_INFO_LOG(&g_framework, "Analysis completed successfully");
            printf("Analysis session completed successfully against %s\n", target_vm);
        } else {
            HGS_ERROR_LOG(&g_framework, "Analysis failed: %d", result);
            printf("Analysis session failed against %s\n", target_vm);
            cleanup_and_exit(1);
        }
    } else {
        // List available VMs
        hgs_vm_info_t* vms = NULL;
        size_t vm_count = 0;
        
        result = hgs_list_vms(&g_framework, &vms, &vm_count);
        if (result == HGS_SUCCESS && vm_count > 0) {
            printf("Available VMs:\n");
            for (size_t i = 0; i < vm_count; i++) {
                printf("  - %s (%s) - %s\n", 
                       vms[i].name, 
                       vms[i].id,
                       vms[i].is_shielded ? "Shielded" : "Standard");
            }
            hgs_free_memory(vms);
        } else {
            printf("No VMs found or unable to enumerate VMs\n");
        }
    }
    
    cleanup_and_exit(0);
}

static void print_usage(const char* program_name)
{
    printf("HGS Manipulation Framework v%s\n", HGS_FRAMEWORK_VERSION);
    printf("A comprehensive framework for testing Hyper-V Host Guardian Service security mechanisms\n\n");
    
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    
    printf("Options:\n");
    printf("  -t, --target-vm VM_NAME    Target VM name for the analysis\n");
    printf("  -m, --mode MODE           Analysis mode (full|attestation|key|policy)\n");
    printf("  -c, --config CONFIG_FILE  Configuration file path\n");
    printf("  -e, --endpoint ENDPOINT   HGS endpoint (default: localhost)\n");
    printf("  -p, --port PORT           HGS port (default: 443)\n");
    printf("  -a, --attestation MODE    Attestation mode (tpm|admin|custom)\n");
    printf("  -l, --list-vms           List available VMs\n");
    printf("  -v, --verbose            Enable verbose logging\n");
    printf("  -d, --debug              Enable debug mode\n");
    printf("  -h, --help               Show this help message\n");
    printf("  -V, --version            Show version information\n\n");
    
    printf("Examples:\n");
    printf("  %s --target-vm \"TestVM\" --mode full\n", program_name);
    printf("  %s --target-vm \"ProdVM\" --mode attestation --config custom.json\n", program_name);
    printf("  %s --list-vms\n", program_name);
    printf("  %s --target-vm \"VM1\" --mode key --verbose\n", program_name);
}

static void print_version(void)
{
    printf("HGS Manipulation Framework v%s\n", HGS_FRAMEWORK_VERSION);
    printf("Build: %s\n", HGS_FRAMEWORK_BUILD);
    printf("Author: HGS-Analyzer contributors\n");
}

static int parse_command_line(int argc, char* argv[], hgs_config_t* config, 
                             char* target_vm, hgs_analysis_mode_t* analysis_mode)
{
    int opt;
    int option_index = 0;
    
    // Default configuration
    strcpy_s(config->hgs_endpoint, sizeof(config->hgs_endpoint), HGS_DEFAULT_ENDPOINT);
    config->hgs_port = HGS_DEFAULT_PORT;
    config->attestation_mode = HGS_ATTESTATION_TPM;
    config->verbose_logging = false;
    config->debug_mode = false;
    strcpy_s(config->log_file, sizeof(config->log_file), "hgs_manipulator.log");
    
    static struct option long_options[] = {
        {"target-vm",    required_argument, 0, 't'},
        {"mode",         required_argument, 0, 'm'},
        {"config",       required_argument, 0, 'c'},
        {"endpoint",     required_argument, 0, 'e'},
        {"port",         required_argument, 0, 'p'},
        {"attestation",  required_argument, 0, 'a'},
        {"list-vms",     no_argument,       0, 'l'},
        {"verbose",      no_argument,       0, 'v'},
        {"debug",        no_argument,       0, 'd'},
        {"help",         no_argument,       0, 'h'},
        {"version",      no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "t:m:c:e:p:a:lvdhV", long_options, &option_index)) != -1) {
        switch (opt) {
            case 't':
                strcpy_s(target_vm, HGS_MAX_VM_NAME_LEN, optarg);
                break;
                
            case 'm':
                if (strcmp(optarg, "full") == 0) {
                    *analysis_mode = HGS_ANALYSIS_FULL;
                } else if (strcmp(optarg, "attestation") == 0) {
                    *analysis_mode = HGS_ANALYSIS_ATTESTATION_ONLY;
                } else if (strcmp(optarg, "key") == 0) {
                    *analysis_mode = HGS_ANALYSIS_KEY_ONLY;
                } else if (strcmp(optarg, "policy") == 0) {
                    *analysis_mode = HGS_ANALYSIS_POLICY_ONLY;
                } else {
                    fprintf(stderr, "Invalid analysis mode: %s\n", optarg);
                    return HGS_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'c':
                if (hgs_parse_config_file(optarg, config) != HGS_SUCCESS) {
                    fprintf(stderr, "Failed to parse config file: %s\n", optarg);
                    return HGS_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'e':
                strcpy_s(config->hgs_endpoint, sizeof(config->hgs_endpoint), optarg);
                break;
                
            case 'p':
                config->hgs_port = (uint16_t)atoi(optarg);
                break;
                
            case 'a':
                if (strcmp(optarg, "tpm") == 0) {
                    config->attestation_mode = HGS_ATTESTATION_TPM;
                } else if (strcmp(optarg, "admin") == 0) {
                    config->attestation_mode = HGS_ATTESTATION_ADMIN;
                } else if (strcmp(optarg, "custom") == 0) {
                    config->attestation_mode = HGS_ATTESTATION_CUSTOM;
                } else {
                    fprintf(stderr, "Invalid attestation mode: %s\n", optarg);
                    return HGS_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'l':
                // List VMs flag - handled in main()
                break;
                
            case 'v':
                config->verbose_logging = true;
                break;
                
            case 'd':
                config->debug_mode = true;
                break;
                
            case 'h':
                print_usage(argv[0]);
                exit(0);
                
            case 'V':
                print_version();
                exit(0);
                
            case '?':
            default:
                return HGS_ERROR_INVALID_PARAM;
        }
    }
    
    return HGS_SUCCESS;
}

static void signal_handler(int signal)
{
    printf("\n Analysis interrupted by user (signal %d)\n", signal);
    cleanup_and_exit(1);
}

static void cleanup_and_exit(int exit_code)
{
    if (g_framework.initialized) {
        hgs_framework_cleanup(&g_framework);
    }
    exit(exit_code);
}
