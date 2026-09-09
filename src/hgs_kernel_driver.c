/**
 * HGS Kernel Driver - Main Driver Implementation
 *
 * Windows kernel driver entry point and device management
 * for HGS manipulation framework
 */

#include "hgs_kernel_driver.h"

// Global driver context
WDFDRIVER g_HgsDriver = NULL;
PHGS_KERNEL_DRIVER g_HgsDriverContext = NULL;

// Forward declarations for cleanup-timer helpers defined later in this file but
// invoked earlier from the timer callback.
VOID HgsKernelCleanupOldPackets(PHGS_KERNEL_DRIVER driver);
VOID HgsKernelUpdateStatistics(PHGS_KERNEL_DRIVER driver);

// Forward declarations for the IOCTL handlers defined later in this file but
// dispatched earlier from HgsEvtIoDeviceControl.
NTSTATUS HgsProcessStartAnalysis(PHGS_KERNEL_DRIVER driverContext, PVOID inputBuffer, size_t inputBufferSize, PVOID outputBuffer, size_t outputBufferSize);
NTSTATUS HgsProcessStopAnalysis(PHGS_KERNEL_DRIVER driverContext, PVOID inputBuffer, size_t inputBufferSize, PVOID outputBuffer, size_t outputBufferSize);
NTSTATUS HgsProcessListVms(PHGS_KERNEL_DRIVER driverContext, PVOID inputBuffer, size_t inputBufferSize, PVOID outputBuffer, size_t outputBufferSize);
NTSTATUS HgsProcessGetStatus(PHGS_KERNEL_DRIVER driverContext, PVOID inputBuffer, size_t inputBufferSize, PVOID outputBuffer, size_t outputBufferSize);
NTSTATUS HgsProcessSampleData(PHGS_KERNEL_DRIVER driverContext, PVOID inputBuffer, size_t inputBufferSize, PVOID outputBuffer, size_t outputBufferSize);

/*
 * Module-level telemetry counters.
 * Incremented under g_TelemetryLock so GetStatus returns accurate values
 * without racing with the observation workitem.
 */
static LONG   g_PacketsObservedTotal = 0;
static LONG   g_ErrorsTotal          = 0;
static KSPIN_LOCK g_TelemetryLock;
static BOOLEAN    g_TelemetryInit = FALSE;

/* Called from HgsEvtDeviceAdd after spin-lock setup. */
static VOID HgsTelemetryInit(VOID)
{
    KeInitializeSpinLock(&g_TelemetryLock);
    g_TelemetryInit = TRUE;
}

VOID HgsTelemetryIncPackets(ULONG n)
{
    InterlockedAdd(&g_PacketsObservedTotal, (LONG)n);
}

VOID HgsTelemetryIncErrors(VOID)
{
    InterlockedIncrement(&g_ErrorsTotal);
}

// Driver entry point
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;

    HgsKernelLogMessage(NULL, "INFO", "HGS Kernel Driver v%s starting...", HGS_DRIVER_VERSION_STRING);

    // Initialize driver configuration
    WDF_DRIVER_CONFIG_INIT(&config, HgsEvtDeviceAdd);
    config.EvtDriverUnload = HgsEvtDriverContextCleanup;

    // Set driver attributes
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ExecutionLevel = WdfExecutionLevelPassive;

    // Create driver object
    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, &g_HgsDriver);
    if (!NT_SUCCESS(status)) {
        HgsKernelLogMessage(NULL, "ERROR", "Failed to create driver object: 0x%x", status);
        return status;
    }

    HgsKernelLogMessage(NULL, "INFO", "HGS Kernel Driver initialized successfully");
    return STATUS_SUCCESS;
}

// Device add event handler
NTSTATUS HgsEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    NTSTATUS status;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;
    PHGS_KERNEL_DRIVER driverContext;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;

    UNREFERENCED_PARAMETER(Driver);

    HgsKernelLogMessage(NULL, "INFO", "Adding HGS device...");

    // Set device name
    RtlInitUnicodeString(&deviceName, HGS_DRIVER_NAME);
    status = WdfDeviceInitAssignName(DeviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        HgsKernelLogMessage(NULL, "ERROR", "Failed to assign device name: 0x%x", status);
        return status;
    }

    // Set device attributes
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, hgs_kernel_driver_t);
    deviceAttributes.EvtCleanupCallback = HgsEvtDeviceContextCleanup;

    // Create device
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        HgsKernelLogMessage(NULL, "ERROR", "Failed to create device: 0x%x", status);
        return status;
    }

    // Get device context
    driverContext = HgsGetDeviceContext(device);
    if (!driverContext) {
        HgsKernelLogMessage(NULL, "ERROR", "Failed to get device context");
        return STATUS_UNSUCCESSFUL;
    }

    // Initialize driver context
    RtlZeroMemory(driverContext, sizeof(hgs_kernel_driver_t));
    driverContext->device = device;
    driverContext->state = HGS_DRIVER_STATE_STOPPED;
    driverContext->initialized = FALSE;
    driverContext->observing = FALSE;

    // Initialize spin lock
    KeInitializeSpinLock(&driverContext->packet_queue_lock);
    InitializeListHead(&driverContext->packet_queue);

    // Initialize telemetry counters
    HgsTelemetryInit();

    // Initialize stop event
    KeInitializeEvent(&driverContext->stop_event, NotificationEvent, FALSE);

    // Create symbolic link
    RtlInitUnicodeString(&symbolicLink, HGS_DRIVER_SYMBOLIC_NAME);
    status = WdfDeviceCreateSymbolicLink(device, &symbolicLink);
    if (!NT_SUCCESS(status)) {
        HgsKernelLogMessage(NULL, "ERROR", "Failed to create symbolic link: 0x%x", status);
        return status;
    }

    // Configure I/O queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = HgsEvtIoDeviceControl;
    queueConfig.EvtIoStop = HgsEvtIoStop;

    // Create I/O queue
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        HgsKernelLogMessage(NULL, "ERROR", "Failed to create I/O queue: 0x%x", status);
        return status;
    }

    driverContext->default_queue = queue;

    // Create cleanup timer
    WDF_TIMER_CONFIG timerConfig;
    WDF_TIMER_CONFIG_INIT(&timerConfig, HgsEvtCleanupTimer);
    timerConfig.AutomaticSerialization = FALSE;

    WDF_OBJECT_ATTRIBUTES timerAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&timerAttributes);
    timerAttributes.ParentObject = device;

    status = WdfTimerCreate(&timerConfig, &timerAttributes, &driverContext->cleanup_timer);
    if (!NT_SUCCESS(status)) {
        HgsKernelLogMessage(NULL, "ERROR", "Failed to create cleanup timer: 0x%x", status);
        return status;
    }

    // Initialize kernel heap
    driverContext->heap_size = 1024 * 1024; // 1MB
    driverContext->kernel_heap = ExAllocatePoolWithTag(
        NonPagedPool,
        driverContext->heap_size,
        'HGSK'
    );

    if (!driverContext->kernel_heap) {
        HgsKernelLogMessage(NULL, "ERROR", "Failed to allocate kernel heap");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(driverContext->kernel_heap, driverContext->heap_size);

    // Initialize framework components
    status = HgsKernelFrameworkInit(driverContext, NULL);
    if (!NT_SUCCESS(status)) {
        HgsKernelLogMessage(NULL, "ERROR", "Failed to initialize framework: 0x%x", status);
        return status;
    }

    // Set global driver context
    g_HgsDriverContext = driverContext;

    HgsKernelLogMessage(NULL, "INFO", "HGS device added successfully");
    return STATUS_SUCCESS;
}

// Driver context cleanup
VOID HgsEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    HgsKernelLogMessage(NULL, "INFO", "HGS Kernel Driver cleanup completed");
}

// Device context cleanup
VOID HgsEvtDeviceContextCleanup(
    _In_ WDFOBJECT DeviceObject
)
{
    PHGS_KERNEL_DRIVER driverContext;

    driverContext = HgsGetDeviceContext((WDFDEVICE)DeviceObject);
    if (!driverContext) {
        return;
    }

    HgsKernelLogMessage(driverContext, "INFO", "Cleaning up HGS device context...");

    // Cleanup framework
    if (driverContext->initialized) {
        HgsKernelFrameworkCleanup(driverContext);
    }

    // Free kernel heap
    if (driverContext->kernel_heap) {
        ExFreePoolWithTag(driverContext->kernel_heap, 'HGSK');
        driverContext->kernel_heap = NULL;
    }

    HgsKernelLogMessage(driverContext, "INFO", "HGS device context cleanup completed");
}

// I/O device control handler
VOID HgsEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PHGS_KERNEL_DRIVER driverContext;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t inputBufferSize = 0;
    size_t outputBufferSize = 0;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    // Get device context
    driverContext = HgsGetDeviceContext(WdfIoQueueGetDevice(Queue));
    if (!driverContext) {
        status = STATUS_UNSUCCESSFUL;
        goto CompleteRequest;
    }

    // Get input buffer
    if (InputBufferLength > 0) {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inputBuffer, &inputBufferSize);
        if (!NT_SUCCESS(status)) {
            HgsKernelErrorLog(driverContext, "Failed to retrieve input buffer: 0x%x", status);
            goto CompleteRequest;
        }
    }

    // Get output buffer
    if (OutputBufferLength > 0) {
        status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outputBuffer, &outputBufferSize);
        if (!NT_SUCCESS(status)) {
            HgsKernelErrorLog(driverContext, "Failed to retrieve output buffer: 0x%x", status);
            goto CompleteRequest;
        }
    }

    // Process IOCTL
    switch (IoControlCode) {
        case IOCTL_HGS_START_ANALYSIS:
            status = HgsProcessStartAnalysis(driverContext, inputBuffer, inputBufferSize, outputBuffer, outputBufferSize);
            break;

        case IOCTL_HGS_STOP_ANALYSIS:
            status = HgsProcessStopAnalysis(driverContext, inputBuffer, inputBufferSize, outputBuffer, outputBufferSize);
            break;

        case IOCTL_HGS_LIST_VMS:
            status = HgsProcessListVms(driverContext, inputBuffer, inputBufferSize, outputBuffer, outputBufferSize);
            break;

        case IOCTL_HGS_GET_STATUS:
            status = HgsProcessGetStatus(driverContext, inputBuffer, inputBufferSize, outputBuffer, outputBufferSize);
            break;

        case IOCTL_HGS_SAMPLE_DATA:
            status = HgsProcessSampleData(driverContext, inputBuffer, inputBufferSize, outputBuffer, outputBufferSize);
            break;

        default:
            HgsKernelWarnLog(driverContext, "Unknown IOCTL: 0x%x", IoControlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

CompleteRequest:
    WdfRequestComplete(Request, status);
}

// I/O stop handler
VOID HgsEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(ActionFlags);

    WdfRequestComplete(Request, STATUS_SUCCESS);
}

// Observe workitem handler
VOID HgsEvtObserveWorkitem(
    _In_ WDFWORKITEM WorkItem
)
{
    PHGS_KERNEL_DRIVER driverContext;
    NTSTATUS status;

    driverContext = HgsGetWorkitemContext(WorkItem);
    if (!driverContext) {
        return;
    }

    HgsKernelDebugLog(driverContext, "RPC observation workitem started");

    // Perform RPC observation
    status = HgsKernelRpcObserverStart(driverContext);
    if (!NT_SUCCESS(status)) {
        HgsKernelErrorLog(driverContext, "RPC observation failed: 0x%x", status);
    }

    HgsKernelDebugLog(driverContext, "RPC observation workitem completed");
}

// Cleanup timer handler
VOID HgsEvtCleanupTimer(
    _In_ WDFTIMER Timer
)
{
    PHGS_KERNEL_DRIVER driverContext;

    driverContext = HgsGetTimerContext(Timer);
    if (!driverContext) {
        return;
    }

    HgsKernelDebugLog(driverContext, "Cleanup timer triggered");

    // Perform periodic cleanup
    if (driverContext->initialized) {
        // Cleanup old packets
        HgsKernelCleanupOldPackets(driverContext);
        
        // Update statistics
        HgsKernelUpdateStatistics(driverContext);
    }
}

// Helper function to get device context
PHGS_KERNEL_DRIVER HgsGetDeviceContext(
    _In_ WDFDEVICE Device
)
{
    return WdfObjectGetTypedContext(Device, hgs_kernel_driver_t);
}

// Helper function to get workitem context
PHGS_KERNEL_DRIVER HgsGetWorkitemContext(
    _In_ WDFWORKITEM WorkItem
)
{
    return (PHGS_KERNEL_DRIVER)WdfWorkItemGetParentObject(WorkItem);
}

// Helper function to get timer context
PHGS_KERNEL_DRIVER HgsGetTimerContext(
    _In_ WDFTIMER Timer
)
{
    return (PHGS_KERNEL_DRIVER)WdfTimerGetParentObject(Timer);
}

// Process start analysis IOCTL
NTSTATUS HgsProcessStartAnalysis(
    _In_ PHGS_KERNEL_DRIVER driverContext,
    _In_ PVOID inputBuffer,
    _In_ size_t inputBufferSize,
    _In_ PVOID outputBuffer,
    _In_ size_t outputBufferSize
)
{
    NTSTATUS status;
    PHGS_START_ANALYSIS_INPUT input;
    PHGS_START_ANALYSIS_OUTPUT output;

    UNREFERENCED_PARAMETER(inputBufferSize);
    UNREFERENCED_PARAMETER(outputBufferSize);

    if (!inputBuffer || !outputBuffer) {
        return STATUS_INVALID_PARAMETER;
    }

    input = (PHGS_START_ANALYSIS_INPUT)inputBuffer;
    output = (PHGS_START_ANALYSIS_OUTPUT)outputBuffer;

    HgsKernelInfoLog(driverContext, "Starting analysis of VM: %ws", input->target_vm);

    // Validate input
    status = HgsKernelValidateVmName(input->target_vm);
    if (!NT_SUCCESS(status)) {
        output->status = status;
        output->error_code = HGS_KERNEL_ERROR_INVALID_PARAM;
        HgsKernelStringCopy(output->message, L"Invalid VM name", sizeof(output->message) / sizeof(WCHAR));
        return status;
    }

    // Run analysis
    status = HgsKernelFrameworkRunAnalysis(driverContext, input->target_vm, input->analysis_mode);
    if (!NT_SUCCESS(status)) {
        output->status = status;
        output->error_code = HGS_KERNEL_ERROR_API_CALL;
        HgsKernelStringCopy(output->message, L"Analysis failed", sizeof(output->message) / sizeof(WCHAR));
        return status;
    }

    output->status = STATUS_SUCCESS;
    output->error_code = HGS_KERNEL_SUCCESS;
    HgsKernelStringCopy(output->message, L"Analysis completed successfully", sizeof(output->message) / sizeof(WCHAR));

    HgsKernelInfoLog(driverContext, "Analysis completed successfully");
    return STATUS_SUCCESS;
}

// Process stop analysis IOCTL
NTSTATUS HgsProcessStopAnalysis(
    _In_ PHGS_KERNEL_DRIVER driverContext,
    _In_ PVOID inputBuffer,
    _In_ size_t inputBufferSize,
    _In_ PVOID outputBuffer,
    _In_ size_t outputBufferSize
)
{
    NTSTATUS status;
    PHGS_START_ANALYSIS_OUTPUT output;

    UNREFERENCED_PARAMETER(inputBuffer);
    UNREFERENCED_PARAMETER(inputBufferSize);
    UNREFERENCED_PARAMETER(outputBufferSize);

    if (!outputBuffer) {
        return STATUS_INVALID_PARAMETER;
    }

    output = (PHGS_START_ANALYSIS_OUTPUT)outputBuffer;

    HgsKernelInfoLog(driverContext, "Stopping analysis...");

    // Stop RPC observation
    status = HgsKernelRpcObserverStop(driverContext);
    if (!NT_SUCCESS(status)) {
        output->status = status;
        output->error_code = HGS_KERNEL_ERROR_RPC_OBSERVE;
        HgsKernelStringCopy(output->message, L"Failed to stop RPC observation", sizeof(output->message) / sizeof(WCHAR));
        return status;
    }

    output->status = STATUS_SUCCESS;
    output->error_code = HGS_KERNEL_SUCCESS;
    HgsKernelStringCopy(output->message, L"Analysis stopped successfully", sizeof(output->message) / sizeof(WCHAR));

    HgsKernelInfoLog(driverContext, "Analysis stopped successfully");
    return STATUS_SUCCESS;
}

// Process list VMs IOCTL
NTSTATUS HgsProcessListVms(
    _In_ PHGS_KERNEL_DRIVER driverContext,
    _In_ PVOID inputBuffer,
    _In_ size_t inputBufferSize,
    _In_ PVOID outputBuffer,
    _In_ size_t outputBufferSize
)
{
    NTSTATUS status;
    PHGS_LIST_VMS_OUTPUT output;

    UNREFERENCED_PARAMETER(inputBuffer);
    UNREFERENCED_PARAMETER(inputBufferSize);
    UNREFERENCED_PARAMETER(outputBufferSize);

    if (!outputBuffer) {
        return STATUS_INVALID_PARAMETER;
    }

    output = (PHGS_LIST_VMS_OUTPUT)outputBuffer;

    HgsKernelInfoLog(driverContext, "Listing VMs...");

    // List VMs
    status = HgsKernelListVms(driverContext, output->vms, &output->vm_count);
    if (!NT_SUCCESS(status)) {
        output->status = status;
        return status;
    }

    output->status = STATUS_SUCCESS;
    HgsKernelInfoLog(driverContext, "Found %u VMs", output->vm_count);
    return STATUS_SUCCESS;
}

// Process get status IOCTL
NTSTATUS HgsProcessGetStatus(
    _In_ PHGS_KERNEL_DRIVER driverContext,
    _In_ PVOID inputBuffer,
    _In_ size_t inputBufferSize,
    _In_ PVOID outputBuffer,
    _In_ size_t outputBufferSize
)
{
    PHGS_GET_STATUS_OUTPUT output;

    UNREFERENCED_PARAMETER(inputBuffer);
    UNREFERENCED_PARAMETER(inputBufferSize);
    UNREFERENCED_PARAMETER(outputBufferSize);

    if (!outputBuffer) {
        return STATUS_INVALID_PARAMETER;
    }

    output = (PHGS_GET_STATUS_OUTPUT)outputBuffer;

    /* Count items currently in the queue (packets not yet dequeued). */
    {
        KIRQL irql;
        PLIST_ENTRY entry;
        UINT32 queued = 0;

        KeAcquireSpinLock(&driverContext->packet_queue_lock, &irql);
        for (entry = driverContext->packet_queue.Flink;
             entry != &driverContext->packet_queue;
             entry = entry->Flink) {
            queued++;
        }
        KeReleaseSpinLock(&driverContext->packet_queue_lock, irql);

        output->state           = driverContext->state;
        output->active_analyses = driverContext->observing ? 1 : 0;
        /* Total packets seen since driver load + currently queued. */
        output->packets_observeed = (UINT32)g_PacketsObservedTotal + queued;
        output->errors_count      = (UINT32)g_ErrorsTotal;
    }

    HgsKernelStringCopy(output->last_error, L"None", sizeof(output->last_error) / sizeof(WCHAR));
    return STATUS_SUCCESS;
}

// Process sample data IOCTL
NTSTATUS HgsProcessSampleData(
    _In_ PHGS_KERNEL_DRIVER driverContext,
    _In_ PVOID inputBuffer,
    _In_ size_t inputBufferSize,
    _In_ PVOID outputBuffer,
    _In_ size_t outputBufferSize
)
{
    NTSTATUS status;
    PHGS_START_ANALYSIS_OUTPUT output;

    UNREFERENCED_PARAMETER(inputBufferSize);
    UNREFERENCED_PARAMETER(outputBufferSize);

    if (!inputBuffer || !outputBuffer) {
        return STATUS_INVALID_PARAMETER;
    }

    output = (PHGS_START_ANALYSIS_OUTPUT)outputBuffer;

    HgsKernelInfoLog(driverContext, "Sampling observed RPC packets...");

    /*
     * Drain the packet queue: dequeue up to HGS_MAX_IRP_QUEUE_SIZE
     * packets, log each one, and tally the count into the telemetry
     * counter.  The caller receives a status message including the
     * number of packets processed.
     */
    {
        KIRQL irql;
        PLIST_ENTRY entry;
        PHGS_KERNEL_RPC_PACKET packet;
        UINT32 sampled = 0;
        WCHAR  msg[256];

        while (sampled < (UINT32)HGS_MAX_IRP_QUEUE_SIZE) {
            KeAcquireSpinLock(&driverContext->packet_queue_lock, &irql);
            if (IsListEmpty(&driverContext->packet_queue)) {
                KeReleaseSpinLock(&driverContext->packet_queue_lock, irql);
                break;
            }
            entry = RemoveHeadList(&driverContext->packet_queue);
            KeReleaseSpinLock(&driverContext->packet_queue_lock, irql);

            packet = CONTAINING_RECORD(entry, hgs_kernel_rpc_packet_t, packet_queue);

            HgsKernelInfoLog(driverContext,
                "Sampled packet: type=0x%x seq=%u len=%u",
                packet->message_type,
                packet->sequence_number,
                packet->payload_length);

            if (packet->payload) {
                HgsKernelFree(driverContext, packet->payload);
            }
            HgsKernelFree(driverContext, packet);

            sampled++;
            InterlockedIncrement(&g_PacketsObservedTotal);
        }

        status = STATUS_SUCCESS;
        RtlStringCbPrintfW(msg, sizeof(msg),
            L"Sampled %u packets; total observed: %d",
            sampled,
            g_PacketsObservedTotal);

        output->status     = STATUS_SUCCESS;
        output->error_code = HGS_KERNEL_SUCCESS;
        HgsKernelStringCopy(output->message, msg, sizeof(output->message) / sizeof(WCHAR));

        HgsKernelInfoLog(driverContext, "Data sampling complete: %u packets processed", sampled);
    }

    return status;
}

// Cleanup old packets
VOID HgsKernelCleanupOldPackets(
    _In_ PHGS_KERNEL_DRIVER driverContext
)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PHGS_KERNEL_RPC_PACKET packet;

    KeAcquireSpinLock(&driverContext->packet_queue_lock, &oldIrql);

    // Cleanup old packets (simplified implementation)
    while (!IsListEmpty(&driverContext->packet_queue)) {
        entry = RemoveHeadList(&driverContext->packet_queue);
        packet = CONTAINING_RECORD(entry, hgs_kernel_rpc_packet_t, packet_queue);
        
        if (packet->payload) {
            HgsKernelFree(driverContext, packet->payload);
        }
        HgsKernelFree(driverContext, packet);
    }

    KeReleaseSpinLock(&driverContext->packet_queue_lock, oldIrql);
}

// Update statistics — called from the periodic cleanup timer
VOID HgsKernelUpdateStatistics(
    _In_ PHGS_KERNEL_DRIVER driverContext
)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    UINT32 queued = 0;

    if (!driverContext) return;

    /* Count queue depth for the log. */
    KeAcquireSpinLock(&driverContext->packet_queue_lock, &irql);
    for (entry = driverContext->packet_queue.Flink;
         entry != &driverContext->packet_queue;
         entry = entry->Flink) {
        queued++;
    }
    KeReleaseSpinLock(&driverContext->packet_queue_lock, irql);

    HgsKernelDebugLog(driverContext,
        "Stats: state=%d observing=%d queue_depth=%u "
        "total_observed=%d total_errors=%d",
        driverContext->state,
        driverContext->observing,
        queued,
        g_PacketsObservedTotal,
        g_ErrorsTotal);
}
