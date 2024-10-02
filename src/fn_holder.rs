use std::ffi::CString;
use windows_sys::{
    core::PCSTR,
    Win32::{
        Foundation::{FreeLibrary, FARPROC, HMODULE},
        System::LibraryLoader::{GetProcAddress, LoadLibraryA},
    },
};

pub trait FnCast: Sized {
    unsafe fn from_untyped(f: unsafe extern "system" fn() -> isize) -> Self;
}

pub struct FnHolder<F: FnCast> {
    lib: HMODULE,
    pub func: F,
}

unsafe impl<F: FnCast> Send for FnHolder<F> {}
unsafe impl<F: FnCast> Sync for FnHolder<F> {}

impl<F: FnCast> Drop for FnHolder<F> {
    fn drop(&mut self) {
        if !self.lib.is_null() {
            unsafe { FreeLibrary(self.lib) };
        }
    }
}

pub fn load_function<F: FnCast>(module_name: &str, function_name: &str) -> Option<FnHolder<F>> {
    unsafe {
        let module_name_cstr = CString::new(module_name).ok()?;
        let function_name_cstr = CString::new(function_name).ok()?;

        let lib = LoadLibraryA(module_name_cstr.as_ptr() as PCSTR);
        if lib.is_null() {
            return None;
        }

        let func_opt: FARPROC = GetProcAddress(lib, function_name_cstr.as_ptr() as PCSTR);
        let Some(func0) = func_opt else {
            FreeLibrary(lib);
            return None;
        };
        let func = F::from_untyped(func0);

        Some(FnHolder { lib, func })
    }
}

#[macro_export]
macro_rules! define_fn_dynamic_load {
    ($fn_type:ident, $fn_signature:ty, $static_var:ident, $load_fn:ident, $module_name:expr, $fn_name:expr) => {
        pub type $fn_type = $fn_signature;

        impl $crate::fn_holder::FnCast for $fn_type {
            unsafe fn from_untyped(f: unsafe extern "system" fn() -> isize) -> Self {
                std::mem::transmute(f)
            }
        }

        #[allow(non_upper_case_globals)]
        static $static_var: std::sync::OnceLock<Option<$crate::fn_holder::FnHolder<$fn_type>>> =
            std::sync::OnceLock::new();

        pub fn $load_fn() -> Option<$fn_type> {
            $static_var
                .get_or_init(|| $crate::fn_holder::load_function($module_name, $fn_name))
                .as_ref()
                .map(|fn_holder| fn_holder.func)
        }
    };
}

/*
// usage
use windows_sys::Win32::Foundation::BOOL;
define_fn_dynamic_load!(
    ProcessPrngFn,
    unsafe extern "system" fn(pbdata: *mut u8, cbdata: usize) -> BOOL,
    PROCESS_PRNG,
    get_fn_process_prng,
    "bcryptprimitives.dll",
    "ProcessPrng"
);
let func = get_fn_process_prng().ok_or("Failed to load function SetInterfaceDnsSettings")?;
*/
