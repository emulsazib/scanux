//! Per-process network isolation with the Windows Filtering Platform, entirely
//! from user mode: BLOCK filters on the ALE connect/accept layers matching the
//! executable's app ID. Other processes stay online.
//!
//! MVP uses a dynamic WFP session: filters disappear if the service dies
//! (fail open, but the process stays suspended by Tier-1). M4 moves to
//! persistent filters with a boot-time reconcile.

use sensor_core::platform::{NetworkControl, PlatformError, PlatformResult};
use sensor_core::ProcessKey;
use std::collections::HashMap;
use std::sync::Mutex;
use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, FWP_E_ALREADY_EXISTS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

/// Scanu sublayer: {6c1e3d2a-5b7f-4c8e-9a10-2f3b4c5d6e7f}
const SUBLAYER: GUID = GUID::from_u128(0x6c1e3d2a_5b7f_4c8e_9a10_2f3b4c5d6e7f);

pub struct WinNetworkControl {
    engine: HANDLE,
    filters: Mutex<HashMap<String, Vec<u64>>>,
}

unsafe impl Send for WinNetworkControl {}
unsafe impl Sync for WinNetworkControl {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(code: u32, what: &str) -> PlatformResult<()> {
    if code == ERROR_SUCCESS.0 { Ok(()) } else { Err(PlatformError::Os(format!("{what}: 0x{code:08x}"))) }
}

impl WinNetworkControl {
    pub fn open() -> PlatformResult<Self> {
        let mut session = FWPM_SESSION0::default();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine = HANDLE::default();
        check(
            unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine) },
            "FwpmEngineOpen0",
        )?;
        let mut name = wide("Scanu process isolation");
        let mut sub = FWPM_SUBLAYER0::default();
        sub.subLayerKey = SUBLAYER;
        sub.displayData.name = windows::core::PWSTR(name.as_mut_ptr());
        sub.weight = 0xFFFF;
        let rc = unsafe { FwpmSubLayerAdd0(engine, &sub, None) };
        if rc != ERROR_SUCCESS.0 && rc != FWP_E_ALREADY_EXISTS.0 as u32 {
            check(rc, "FwpmSubLayerAdd0")?;
        }
        Ok(Self { engine, filters: Mutex::new(HashMap::new()) })
    }
}

impl NetworkControl for WinNetworkControl {
    fn block_process(&self, _p: ProcessKey, image_path: &str) -> PlatformResult<()> {
        let key = image_path.to_lowercase();
        if self.filters.lock().unwrap().contains_key(&key) {
            return Ok(());
        }
        let path = wide(image_path);
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        check(unsafe { FwpmGetAppIdFromFileName0(PCWSTR(path.as_ptr()), &mut app_id) }, "FwpmGetAppIdFromFileName0")?;
        let mut ids = Vec::new();
        let mut name = wide("Scanu: isolate process");
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ] {
            let mut cond = FWPM_FILTER_CONDITION0::default();
            cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
            cond.conditionValue.Anonymous.byteBlob = app_id;
            let mut f = FWPM_FILTER0::default();
            f.layerKey = layer;
            f.subLayerKey = SUBLAYER;
            f.displayData.name = windows::core::PWSTR(name.as_mut_ptr());
            f.action.r#type = FWP_ACTION_BLOCK;
            f.weight.r#type = FWP_UINT8;
            f.weight.Anonymous.uint8 = 15;
            f.numFilterConditions = 1;
            f.filterCondition = &mut cond;
            let mut id = 0u64;
            let rc = unsafe { FwpmFilterAdd0(self.engine, &f, None, Some(&mut id)) };
            if rc != ERROR_SUCCESS.0 {
                for id in &ids {
                    unsafe { FwpmFilterDeleteById0(self.engine, *id) };
                }
                unsafe { FwpmFreeMemory0(&mut (app_id as *mut core::ffi::c_void)) };
                return check(rc, "FwpmFilterAdd0");
            }
            ids.push(id);
        }
        unsafe { FwpmFreeMemory0(&mut (app_id as *mut core::ffi::c_void)) };
        self.filters.lock().unwrap().insert(key, ids);
        Ok(())
    }

    fn unblock_process(&self, _p: ProcessKey, image_path: &str) -> PlatformResult<()> {
        if let Some(ids) = self.filters.lock().unwrap().remove(&image_path.to_lowercase()) {
            for id in ids {
                check(unsafe { FwpmFilterDeleteById0(self.engine, id) }, "FwpmFilterDeleteById0")?;
            }
        }
        Ok(())
    }
}

impl Drop for WinNetworkControl {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.engine) };
    }
}
