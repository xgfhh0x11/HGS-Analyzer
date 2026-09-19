/**
 * HGS Kernel Driver - Main Header
 *
 * Windows kernel driver for HGS manipulation framework
 * Designed to run in kernel space for maximum privilege and stealth
 *
 * Author: HGS-Analyzer contributors
 * Version: 2.0.0 (Kernel Edition)
 */

#ifndef HGS_KERNEL_DRIVER_H
#define HGS_KERNEL_DRIVER_H

// Kernel-mode (KMDF) include set. The previous revision pulled a large set
// of device-class headers (keyboard/mouse/serial/scsi/disk/tape/1394/usb/...)
// and user-mode CRT/Win32 headers (windef.h, winioctl.h, stdio/stdlib/string.h)
// that do not belong in a kernel driver — ntddpcmcia.h is not even shipped in
// recent WDKs, which broke the build outright. Only what the driver uses:
#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdf.h>
#include <stdint.h>
#include <stdbool.h>

// INVALID_HANDLE_VALUE is a user-mode (handleapi.h) constant; provide the same
// sentinel for kernel handle guards since it is not declared by the WDK headers.
#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif

// Driver version
#define HGS_DRIVER_VERSION_MAJOR 2
#define HGS_DRIVER_VERSION_MINOR 0
#define HGS_DRIVER_VERSION_BUILD 0
#define HGS_DRIVER_VERSION_STRING "2.0.0"

// Driver information
#define HGS_DRIVER_NAME L"\\Device\\HgsAnalyzer"
#define HGS_DRIVER_SYMBOLIC_NAME L"\\DosDevices\\HgsAnalyzer"
#define HGS_DRIVER_DEVICE_NAME L"HgsAnalyzer"

// IOCTL codes
#define HGS_IOCTL_BASE 0x8000
#define IOCTL_HGS_START_ANALYSIS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HGS_IOCTL_BASE + 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HGS_STOP_ANALYSIS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HGS_IOCTL_BASE + 0x02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HGS_LIST_VMS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HGS_IOCTL_BASE + 0x03, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HGS_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HGS_IOCTL_BASE + 0x04, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HGS_SAMPLE_DATA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HGS_IOCTL_BASE + 0x05, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Error codes
#define HGS_KERNEL_SUCCESS 0
#define HGS_KERNEL_ERROR_INVALID_PARAM -1
#define HGS_KERNEL_ERROR_MEMORY_ALLOC -2
#define HGS_KERNEL_ERROR_API_CALL -3
#define HGS_KERNEL_ERROR_RPC_OBSERVE -4
#define HGS_KERNEL_ERROR_ATTESTATION -5
#define HGS_KERNEL_ERROR_KEY_PROTECTOR -6
#define HGS_KERNEL_ERROR_VM_POLICY -7
#define HGS_KERNEL_ERROR_CLEANUP -8
#define HGS_KERNEL_ERROR_ACCESS_DENIED -9
#define HGS_KERNEL_ERROR_INVALID_STATE -10

// Kernel-specific constants
#define HGS_MAX_VM_NAME_LEN 256
#define HGS_MAX_ATTESTATION_DATA_LEN 4096
#define HGS_MAX_RPC_PACKET_SIZE 8192
#define HGS_KERNEL_STACK_SIZE 16384
#define HGS_MAX_IRP_QUEUE_SIZE 32

// RPC Message Types (Kernel)
#define HGS_KERNEL_MSG_ATTESTATION_REQUEST 0x01
#define HGS_KERNEL_MSG_ATTESTATION_RESPONSE 0x02
#define HGS_KERNEL_MSG_KEY_REQUEST 0x10
#define HGS_KERNEL_MSG_KEY_RESPONSE 0x11
#define HGS_KERNEL_MSG_POLICY_UPDATE 0x20

// Attestation Modes (Kernel)
typedef enum {
    HGS_KERNEL_ATTESTATION_TPM = 1,
    HGS_KERNEL_ATTESTATION_ADMIN = 2,
    HGS_KERNEL_ATTESTATION_CUSTOM = 3
} hgs_kernel_attestation_mode_t;

// Analysis Modes (Kernel)
typedef enum {
    HGS_KERNEL_ANALYSIS_FULL = 1,
    HGS_KERNEL_ANALYSIS_ATTESTATION_ONLY = 2,
    HGS_KERNEL_ANALYSIS_KEY_ONLY = 3,
    HGS_KERNEL_ANALYSIS_POLICY_ONLY = 4
} hgs_kernel_analysis_mode_t;

// Driver State
typedef enum {
    HGS_DRIVER_STATE_STOPPED = 0,
    HGS_DRIVER_STATE_STARTING = 1,
    HGS_DRIVER_STATE_RUNNING = 2,
    HGS_DRIVER_STATE_STOPPING = 3,
    HGS_DRIVER_STATE_ERROR = 4
} hgs_driver_state_t;

// Kernel RPC Packet Structure
typedef struct {
    LIST_ENTRY packet_queue;    /* intrusive list link for driver->packet_queue */
    UINT32 version;
    UINT32 message_type;
    UINT32 sequence_number;
    UINT32 payload_length;
    PVOID payload;
    UCHAR checksum[16];
} hgs_kernel_rpc_packet_t, *PHGS_KERNEL_RPC_PACKET;

// Kernel Attestation Data Structure
typedef struct {
    hgs_kernel_attestation_mode_t mode;
    PVOID tpm_data;
    SIZE_T tpm_data_len;
    PVOID certificates;
    SIZE_T certificates_len;
    PVOID signatures;
    SIZE_T signatures_len;
    ULARGE_INTEGER timestamp;
} hgs_kernel_attestation_data_t, *PHGS_KERNEL_ATTESTATION_DATA;

// Kernel VM Information Structure
typedef struct {
    WCHAR name[HGS_MAX_VM_NAME_LEN];
    WCHAR id[64];
    BOOLEAN is_shielded;
    BOOLEAN is_running;
    UINT32 state;
} hgs_kernel_vm_info_t, *PHGS_KERNEL_VM_INFO;

// Kernel Key Protector Structure
typedef struct {
    PVOID key_data;
    SIZE_T key_data_len;
    PVOID protector_data;
    SIZE_T protector_data_len;
    UINT32 algorithm_id;
    ULARGE_INTEGER creation_time;
} hgs_kernel_key_protector_t, *PHGS_KERNEL_KEY_PROTECTOR;

// Kernel Driver Configuration
typedef struct {
    WCHAR hgs_endpoint[256];
    UINT16 hgs_port;
    hgs_kernel_attestation_mode_t attestation_mode;
    BOOLEAN verbose_logging;
    BOOLEAN debug_mode;
    WCHAR log_file[256];
} hgs_kernel_config_t, *PHGS_KERNEL_CONFIG;

// Main Kernel Driver Structure
typedef struct {
    WDFDEVICE device;
    WDFQUEUE default_queue;
    hgs_kernel_config_t config;
    hgs_driver_state_t state;
    BOOLEAN initialized;
    BOOLEAN observing;
    WDFWORKITEM observe_workitem;
    KSPIN_LOCK packet_queue_lock;
    LIST_ENTRY packet_queue;
    KEVENT stop_event;
    WDFTIMER cleanup_timer;
    PVOID kernel_heap;
    SIZE_T heap_size;
} hgs_kernel_driver_t, *PHGS_KERNEL_DRIVER;

// Register hgs_kernel_driver_t as a WDF object context type. This generates the
// _WDF_hgs_kernel_driver_t_TYPE_INFO descriptor that WdfObjectGetTypedContext()
// and WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE() rely on.
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(hgs_kernel_driver_t, HgsGetContextFromHandle)

// Context accessor helpers (defined in hgs_kernel_driver.c). Declared here so
// callers see the correct prototype before the definitions later in the file.
PHGS_KERNEL_DRIVER HgsGetDeviceContext(_In_ WDFDEVICE Device);
PHGS_KERNEL_DRIVER HgsGetWorkitemContext(_In_ WDFWORKITEM WorkItem);
PHGS_KERNEL_DRIVER HgsGetTimerContext(_In_ WDFTIMER Timer);

// IOCTL Input/Output Structures
typedef struct {
    WCHAR target_vm[HGS_MAX_VM_NAME_LEN];
    hgs_kernel_analysis_mode_t analysis_mode;
    hgs_kernel_config_t config;
} hgs_start_analysis_input_t, *PHGS_START_ANALYSIS_INPUT;

typedef struct {
    NTSTATUS status;
    UINT32 error_code;
    WCHAR message[256];
} hgs_start_analysis_output_t, *PHGS_START_ANALYSIS_OUTPUT;

typedef struct {
    hgs_kernel_vm_info_t vms[32];
    UINT32 vm_count;
    NTSTATUS status;
} hgs_list_vms_output_t, *PHGS_LIST_VMS_OUTPUT;

typedef struct {
    hgs_driver_state_t state;
    UINT32 active_analyses;
    UINT32 packets_observeed;
    UINT32 errors_count;
    WCHAR last_error[256];
} hgs_get_status_output_t, *PHGS_GET_STATUS_OUTPUT;

// Function Declarations

// Driver Entry and Cleanup
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD HgsEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP HgsEvtDriverContextCleanup;

// Device Management
EVT_WDF_DEVICE_CONTEXT_CLEANUP HgsEvtDeviceContextCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL HgsEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_STOP HgsEvtIoStop;

// Kernel Framework Functions
NTSTATUS HgsKernelFrameworkInit(PHGS_KERNEL_DRIVER driver, PHGS_KERNEL_CONFIG config);
NTSTATUS HgsKernelFrameworkCleanup(PHGS_KERNEL_DRIVER driver);
NTSTATUS HgsKernelFrameworkRunAnalysis(PHGS_KERNEL_DRIVER driver, const WCHAR* target_vm, hgs_kernel_analysis_mode_t mode);

// Kernel RPC Observer Functions
NTSTATUS HgsKernelRpcObserverInit(PHGS_KERNEL_DRIVER driver);
NTSTATUS HgsKernelRpcObserverStart(PHGS_KERNEL_DRIVER driver);
NTSTATUS HgsKernelRpcObserverStop(PHGS_KERNEL_DRIVER driver);
NTSTATUS HgsKernelRpcObserverCleanup(PHGS_KERNEL_DRIVER driver);
NTSTATUS HgsKernelSampleFakeAttestation(PHGS_KERNEL_DRIVER driver, PHGS_KERNEL_ATTESTATION_DATA attestation);
NTSTATUS HgsKernelListVms(PHGS_KERNEL_DRIVER driver, PHGS_KERNEL_VM_INFO* vms, PUINT32 vm_count);

// Kernel Attestation Fuzzer Functions
NTSTATUS HgsKernelAttestationFuzzerInit(PHGS_KERNEL_DRIVER driver);
NTSTATUS HgsKernelGenerateFakeAttestation(PHGS_KERNEL_DRIVER driver, PHGS_KERNEL_ATTESTATION_DATA attestation);
NTSTATUS HgsKernelFuzzTpmData(PHGS_KERNEL_DRIVER driver, PVOID* tpm_data, PSIZE_T tpm_data_len);
NTSTATUS HgsKernelModelCertificates(PHGS_KERNEL_DRIVER driver, PVOID* cert_data, PSIZE_T cert_data_len);
NTSTATUS HgsKernelAttestationFuzzerCleanup(PHGS_KERNEL_DRIVER driver);

// Kernel Key Protector Model Functions
NTSTATUS HgsKernelKeyProtectorModelInit(PHGS_KERNEL_DRIVER driver);
NTSTATUS HgsKernelModelKeyProtector(PHGS_KERNEL_DRIVER driver, const WCHAR* vm_name, PHGS_KERNEL_KEY_PROTECTOR protector);
NTSTATUS HgsKernelExtractVmKeys(PHGS_KERNEL_DRIVER driver, const WCHAR* vm_name, PHGS_KERNEL_KEY_PROTECTOR protector);
NTSTATUS HgsKernelSampleKeyProtector(PHGS_KERNEL_DRIVER driver, const WCHAR* vm_name, PHGS_KERNEL_KEY_PROTECTOR protector);
NTSTATUS HgsKernelKeyProtectorModelCleanup(PHGS_KERNEL_DRIVER driver);

// Kernel VM Policy Sampler Functions
NTSTATUS HgsKernelVmPolicySamplerInit(PHGS_KERNEL_DRIVER driver);
NTSTATUS HgsKernelSampleVmPolicy(PHGS_KERNEL_DRIVER driver, const WCHAR* vm_name, const WCHAR* policy_data);
NTSTATUS HgsKernelModifyVmSecuritySettings(PHGS_KERNEL_DRIVER driver, const WCHAR* vm_name);
NTSTATUS HgsKernelVmPolicySamplerCleanup(PHGS_KERNEL_DRIVER driver);

// Kernel Utility Functions
NTSTATUS HgsKernelLogMessage(PHGS_KERNEL_DRIVER driver, const CHAR* level, const CHAR* message, ...);
NTSTATUS HgsKernelAllocateMemory(PHGS_KERNEL_DRIVER driver, PVOID* ptr, SIZE_T size);
NTSTATUS HgsKernelFreeMemory(PHGS_KERNEL_DRIVER driver, PVOID ptr);
NTSTATUS HgsKernelValidateVmName(const WCHAR* vm_name);
NTSTATUS HgsKernelCalculateChecksum(const UCHAR* data, SIZE_T data_len, PUCHAR checksum);

// Kernel Windows API Helper Functions
NTSTATUS HgsKernelGetTpmInfo(PHGS_KERNEL_DRIVER driver, PVOID* tpm_data, PSIZE_T tpm_data_len);
NTSTATUS GenerateFakeKernelTpmData(PHGS_KERNEL_DRIVER driver, PVOID* tpm_data, PSIZE_T tpm_data_len);
NTSTATUS GenerateFakeKernelVmData(PHGS_KERNEL_DRIVER driver, PHGS_KERNEL_VM_INFO* vms, PUINT32 vm_count);
NTSTATUS HgsKernelGetSystemCertificates(PHGS_KERNEL_DRIVER driver, PVOID* cert_data, PSIZE_T cert_data_len);
NTSTATUS HgsKernelEnumerateHypervVms(PHGS_KERNEL_DRIVER driver, PHGS_KERNEL_VM_INFO* vms, PUINT32 vm_count);
NTSTATUS HgsKernelHookRpcFunctions(PHGS_KERNEL_DRIVER driver);
NTSTATUS HgsKernelUnhookRpcFunctions(PHGS_KERNEL_DRIVER driver);

// Kernel Workitem Functions
EVT_WDF_WORKITEM HgsEvtObserveWorkitem;
EVT_WDF_TIMER HgsEvtCleanupTimer;

// Global driver handles (defined in hgs_kernel_driver.c, referenced by the
// RPC observer and other translation units).
extern WDFDRIVER g_HgsDriver;
extern PHGS_KERNEL_DRIVER g_HgsDriverContext;

// Telemetry counters (defined in hgs_kernel_driver.c)
VOID HgsTelemetryIncPackets(ULONG n);
VOID HgsTelemetryIncErrors(VOID);

// Kernel Debug and Logging Macros
#ifdef DBG
#define HGS_KERNEL_DEBUG_LOG(driver, format, ...) \
    HgsKernelLogMessage(driver, "DEBUG", format, ##__VA_ARGS__)
#else
#define HGS_KERNEL_DEBUG_LOG(driver, format, ...)
#endif

#define HGS_KERNEL_INFO_LOG(driver, format, ...) \
    HgsKernelLogMessage(driver, "INFO", format, ##__VA_ARGS__)

#define HGS_KERNEL_WARN_LOG(driver, format, ...) \
    HgsKernelLogMessage(driver, "WARN", format, ##__VA_ARGS__)

#define HGS_KERNEL_ERROR_LOG(driver, format, ...) \
    HgsKernelLogMessage(driver, "ERROR", format, ##__VA_ARGS__)

// The implementation files call these short logging names; wire them to the
// single HgsKernelLogMessage sink so the level string stays consistent.
#define HgsKernelDebugLog(driver, format, ...) \
    HgsKernelLogMessage(driver, "DEBUG", format, ##__VA_ARGS__)
#define HgsKernelInfoLog(driver, format, ...) \
    HgsKernelLogMessage(driver, "INFO", format, ##__VA_ARGS__)
#define HgsKernelWarnLog(driver, format, ...) \
    HgsKernelLogMessage(driver, "WARN", format, ##__VA_ARGS__)
#define HgsKernelErrorLog(driver, format, ...) \
    HgsKernelLogMessage(driver, "ERROR", format, ##__VA_ARGS__)

// Kernel Memory Management Macros
#define HGS_KERNEL_ALLOCATE(driver, ptr, size) \
    HgsKernelAllocateMemory(driver, (PVOID*)&(ptr), size)

#define HGS_KERNEL_FREE(driver, ptr) \
    HgsKernelFreeMemory(driver, ptr)

// Kernel String Macros
#define HGS_KERNEL_STRING_INIT(str, max_len) \
    RtlZeroMemory(str, max_len * sizeof(WCHAR))

#define HGS_KERNEL_STRING_COPY(dst, src, max_len) \
    RtlStringCbCopyW(dst, max_len * sizeof(WCHAR), src)

#define HGS_KERNEL_STRING_LENGTH(str) \
    wcslen(str)

// Short function-style aliases used throughout the implementation files. They
// map onto the canonical helpers/macros above so the two naming styles agree.
#define HgsKernelFree(driver, ptr)              HgsKernelFreeMemory(driver, ptr)
#define HgsKernelStringInit(str, max_len)       HGS_KERNEL_STRING_INIT(str, max_len)
#define HgsKernelStringCopy(dst, src, max_len)  HGS_KERNEL_STRING_COPY(dst, src, max_len)
#define HgsKernelStringLength(str)              HGS_KERNEL_STRING_LENGTH(str)

// Kernel Status Macros. NOTE: HGS_KERNEL_SUCCESS is already defined above as
// the integer status code 0; do not redefine it here as a function-like macro
// or bare uses of the constant stop expanding. Use distinct names for the
// NTSTATUS predicate helpers.
#define HGS_KERNEL_STATUS_SUCCEEDED(status) \
    (NT_SUCCESS(status))

#define HGS_KERNEL_FAILED(status) \
    (!NT_SUCCESS(status))

#endif // HGS_KERNEL_DRIVER_H
