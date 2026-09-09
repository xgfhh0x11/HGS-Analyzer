/**
 * HGS Manipulation Framework - Utility Functions
 * 
 * Common utility functions for the HGS manipulation framework.
 */

#include "hgs_manipulator.h"
#include <wbemcli.h>

int hgs_get_tpm_info(uint8_t** tpm_data, size_t* tpm_data_len)
{
    if (!tpm_data || !tpm_data_len) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    // Initialize TPM subsystem
    TBS_CONTEXT_PARAMS2 tbs_params = {0};
    tbs_params.version = TBS_CONTEXT_VERSION_TWO;
    tbs_params.includeTpm12 = TRUE;
    tbs_params.includeTpm20 = TRUE;
    
    TBS_HCONTEXT tbs_context = 0;
    TBS_RESULT tbs_result = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&tbs_params, &tbs_context);
    if (tbs_result != TBS_SUCCESS) {
        return HGS_ERROR_API_CALL;
    }
    
    // Get TPM information
    UINT32 tpm_info_size = 0;
    tbs_result = Tbsi_GetDeviceInfo(sizeof(tpm_info_size), &tpm_info_size, NULL);
    if (tbs_result != TBS_SUCCESS) {
        Tbsip_Context_Close(tbs_context);
        return HGS_ERROR_API_CALL;
    }
    
    // Allocate memory for TPM info
    int result = hgs_allocate_memory((void**)tpm_data, tpm_info_size);
    if (result != HGS_SUCCESS) {
        Tbsip_Context_Close(tbs_context);
        return result;
    }
    
    // Get TPM device info
    tbs_result = Tbsi_GetDeviceInfo(tpm_info_size, &tpm_info_size, *tpm_data);
    if (tbs_result != TBS_SUCCESS) {
        hgs_free_memory(*tpm_data);
        *tpm_data = NULL;
        *tpm_data_len = 0;
        Tbsip_Context_Close(tbs_context);
        return HGS_ERROR_API_CALL;
    }
    
    *tpm_data_len = tpm_info_size;
    Tbsip_Context_Close(tbs_context);
    
    return HGS_SUCCESS;
}

int hgs_get_system_certificates(uint8_t** cert_data, size_t* cert_data_len)
{
    if (!cert_data || !cert_data_len) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    // Open system certificate store
    HCERTSTORE hStore = CertOpenSystemStoreA(0, "MY");
    if (!hStore) {
        return HGS_ERROR_API_CALL;
    }
    
    // Enumerate certificates
    PCCERT_CONTEXT pCert = NULL;
    size_t total_size = 0;
    
    // First pass: calculate total size
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        total_size += pCert->cbCertEncoded;
    }
    
    if (total_size == 0) {
        CertCloseStore(hStore, 0);
        return HGS_ERROR_API_CALL;
    }
    
    // Allocate memory for certificates
    int result = hgs_allocate_memory((void**)cert_data, total_size);
    if (result != HGS_SUCCESS) {
        CertCloseStore(hStore, 0);
        return result;
    }
    
    // Second pass: copy certificates
    pCert = NULL;
    size_t offset = 0;
    
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        memcpy(*cert_data + offset, pCert->pbCertEncoded, pCert->cbCertEncoded);
        offset += pCert->cbCertEncoded;
    }
    
    *cert_data_len = total_size;
    CertCloseStore(hStore, 0);
    
    return HGS_SUCCESS;
}

int hgs_enumerate_hyperv_vms(hgs_vm_info_t** vms, size_t* vm_count)
{
    if (!vms || !vm_count) {
        return HGS_ERROR_INVALID_PARAM;
    }
    
    // Initialize COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return HGS_ERROR_API_CALL;
    }
    
    // Initialize WMI
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                         IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return HGS_ERROR_API_CALL;
    }
    
    // Connect to WMI
    hr = pLoc->lpVtbl->ConnectServer(pLoc, L"ROOT\\virtualization\\v2", NULL, NULL, 0, 0, 0, &pSvc);
    if (FAILED(hr)) {
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return HGS_ERROR_API_CALL;
    }
    
    // Set security levels
    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return HGS_ERROR_API_CALL;
    }
    
    // Query for VMs
    hr = pSvc->lpVtbl->ExecQuery(pSvc, L"WQL", L"SELECT * FROM Msvm_ComputerSystem", 
                                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) {
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return HGS_ERROR_API_CALL;
    }
    
    // Count VMs
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    size_t count = 0;
    
    while (pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK && uReturn > 0) {
        count++;
        pclsObj->lpVtbl->Release(pclsObj);
        pclsObj = NULL;
    }
    
    if (count == 0) {
        pEnumerator->lpVtbl->Release(pEnumerator);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        *vms = NULL;
        *vm_count = 0;
        return HGS_SUCCESS;
    }
    
    // Allocate memory for VMs
    int result = hgs_allocate_memory((void**)vms, count * sizeof(hgs_vm_info_t));
    if (result != HGS_SUCCESS) {
        pEnumerator->lpVtbl->Release(pEnumerator);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return result;
    }
    
    // Reset enumerator
    pEnumerator->lpVtbl->Release(pEnumerator);
    hr = pSvc->lpVtbl->ExecQuery(pSvc, L"WQL", L"SELECT * FROM Msvm_ComputerSystem", 
                                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) {
        hgs_free_memory(*vms);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return HGS_ERROR_API_CALL;
    }
    
    // Populate VM information
    size_t index = 0;
    while (pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK && uReturn > 0) {
        if (index < count) {
            // Get VM name
            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pclsObj->lpVtbl->Get(pclsObj, L"ElementName", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, 
                                   (*vms)[index].name, sizeof((*vms)[index].name), NULL, NULL);
                VariantClear(&vtProp);
            }
            
            // Get VM ID
            VariantInit(&vtProp);
            hr = pclsObj->lpVtbl->Get(pclsObj, L"Name", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, 
                                   (*vms)[index].id, sizeof((*vms)[index].id), NULL, NULL);
                VariantClear(&vtProp);
            }
            
            // Get VM state
            VariantInit(&vtProp);
            hr = pclsObj->lpVtbl->Get(pclsObj, L"EnabledState", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_I2) {
                (*vms)[index].state = vtProp.iVal;
                (*vms)[index].is_running = (vtProp.iVal == 2); // Running state
                VariantClear(&vtProp);
            }
            
            // Check if VM is shielded (simplified check)
            (*vms)[index].is_shielded = false; // This would require more complex logic
            
            index++;
        }
        
        pclsObj->lpVtbl->Release(pclsObj);
        pclsObj = NULL;
    }
    
    *vm_count = count;
    
    // Cleanup
    pEnumerator->lpVtbl->Release(pEnumerator);
    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();
    
    return HGS_SUCCESS;
}

int hgs_hook_rpc_functions(void)
{
    // This function would install API hooks for RPC functions
    // Implementation would use Detours or similar hooking library
    
    return HGS_SUCCESS;
}

int hgs_unhook_rpc_functions(void)
{
    // This function would remove API hooks for RPC functions
    // Implementation would use Detours or similar hooking library
    
    return HGS_SUCCESS;
}
