#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::slice;
use std::sync::Arc;

use windows_sys::Win32::System::Rpc::{
    I_RpcFreeBuffer, I_RpcGetBuffer, I_RpcSendReceive, RPC_C_LISTEN_MAX_CALLS_DEFAULT,
    RPC_C_PROTSEQ_MAX_REQS_DEFAULT, RPC_CLIENT_INTERFACE, RPC_DISPATCH_FUNCTION,
    RPC_DISPATCH_TABLE, RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH, RPC_MESSAGE, RPC_S_ALREADY_LISTENING,
    RPC_S_CALL_FAILED, RPC_S_DUPLICATE_ENDPOINT, RPC_SERVER_INTERFACE, RPC_STATUS,
    RPC_SYNTAX_IDENTIFIER, RPC_VERSION, RpcBindingFree, RpcBindingFromStringBindingW,
    RpcMgmtStopServerListening, RpcRaiseException, RpcServerListen, RpcServerRegisterIfEx,
    RpcServerUnregisterIf, RpcServerUseProtseqEpW, RpcStringBindingComposeW, RpcStringFreeW,
};
use windows_sys::core::{GUID, PWSTR};

const PROTSEQ_NCALRPC: &[u16] = &[110, 99, 97, 108, 114, 112, 99, 0]; // "ncalrpc\0"
const NDR_SYNTAX_GUID: GUID = GUID {
    data1: 0x8A885D04,
    data2: 0x1CEB,
    data3: 0x11C9,
    data4: [0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60],
};
const NDR_SYNTAX_VERSION: RPC_VERSION = RPC_VERSION {
    MajorVersion: 2,
    MinorVersion: 0,
};
const NDR_LOCAL_DATA_REPRESENTATION: u32 = 0x10;

fn wide_null(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = OsStr::new(s).encode_wide().collect();
    v.push(0);
    v
}

#[derive(Debug, Clone)]
pub struct Error {
    code: RPC_STATUS,
    context: &'static str,
}

impl Error {
    pub fn new(code: RPC_STATUS, context: &'static str) -> Self {
        Self { code, context }
    }

    pub fn code(&self) -> RPC_STATUS {
        self.code
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (RPC status {})", self.context, self.code)
    }
}

impl std::error::Error for Error {}

pub trait Handler: Send + Sync {
    fn handle(&self, proc_num: u32, request: &[u8]) -> Result<Vec<u8>, Error>;
}

struct ServerContext {
    handler: Arc<dyn Handler>,
}

unsafe extern "system" fn dispatch_trampoline(message: *mut RPC_MESSAGE) {
    let Some(msg) = (unsafe { message.as_mut() }) else {
        unsafe { RpcRaiseException(RPC_S_CALL_FAILED) };
        return;
    };
    let if_ptr = msg.RpcInterfaceInformation as *const RPC_SERVER_INTERFACE;
    if if_ptr.is_null() {
        unsafe { RpcRaiseException(RPC_S_CALL_FAILED) };
        return;
    }
    let ctx_ptr = unsafe { (*if_ptr).InterpreterInfo } as *const ServerContext;
    if ctx_ptr.is_null() {
        unsafe { RpcRaiseException(RPC_S_CALL_FAILED) };
        return;
    }
    let handler = unsafe { &(*ctx_ptr).handler };
    let request = if msg.Buffer.is_null() || msg.BufferLength == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(msg.Buffer as *const u8, msg.BufferLength as usize) }
    };

    match handler.handle(msg.ProcNum, request) {
        Ok(response) => {
            unsafe {
                let _ = I_RpcFreeBuffer(msg);
            }
            if response.is_empty() {
                msg.Buffer = ptr::null_mut();
                msg.BufferLength = 0;
            } else {
                msg.BufferLength = response.len() as u32;
                let status = unsafe { I_RpcGetBuffer(msg) };
                if status != 0 {
                    unsafe { RpcRaiseException(status) };
                    return;
                }
                unsafe {
                    ptr::copy_nonoverlapping(
                        response.as_ptr(),
                        msg.Buffer as *mut u8,
                        response.len(),
                    );
                }
            }
        }
        Err(err) => unsafe {
            RpcRaiseException(err.code());
        },
    }
}

pub struct Server {
    server_if: *mut RPC_SERVER_INTERFACE,
    dispatch_table: *mut RPC_DISPATCH_TABLE,
    _dispatch_entries: Box<[RPC_DISPATCH_FUNCTION]>,
    ctx: *mut ServerContext,
}

unsafe impl Send for Server {}
unsafe impl Sync for Server {}

impl Server {
    pub fn start(
        uuid: GUID,
        version: (u16, u16),
        endpoint: &str,
        proc_count: u32,
        handler: Arc<dyn Handler>,
    ) -> Result<Self, Error> {
        if proc_count == 0 {
            return Err(Error::new(RPC_S_CALL_FAILED, "proc_count must be > 0"));
        }

        let endpoint_w = wide_null(endpoint);
        let status = unsafe {
            RpcServerUseProtseqEpW(
                PROTSEQ_NCALRPC.as_ptr(),
                RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
                endpoint_w.as_ptr(),
                ptr::null(),
            )
        };
        if status != 0 && status != RPC_S_DUPLICATE_ENDPOINT {
            return Err(Error::new(status, "RpcServerUseProtseqEpW"));
        }

        let mut entries = vec![None; proc_count as usize].into_boxed_slice();
        for entry in entries.iter_mut() {
            *entry = Some(dispatch_trampoline as unsafe extern "system" fn(*mut RPC_MESSAGE));
        }
        let entries_ptr = entries.as_mut_ptr();
        let dispatch_table_box = Box::new(RPC_DISPATCH_TABLE {
            DispatchTableCount: proc_count,
            DispatchTable: unsafe { mem::transmute(entries_ptr) },
            Reserved: 0,
        });
        let dispatch_table_ptr = Box::into_raw(dispatch_table_box);

        let ctx_ptr = Box::into_raw(Box::new(ServerContext { handler }));

        let server_if_box = Box::new(RPC_SERVER_INTERFACE {
            Length: mem::size_of::<RPC_SERVER_INTERFACE>() as u32,
            InterfaceId: RPC_SYNTAX_IDENTIFIER {
                SyntaxGUID: uuid,
                SyntaxVersion: RPC_VERSION {
                    MajorVersion: version.0,
                    MinorVersion: version.1,
                },
            },
            TransferSyntax: RPC_SYNTAX_IDENTIFIER {
                SyntaxGUID: NDR_SYNTAX_GUID,
                SyntaxVersion: NDR_SYNTAX_VERSION,
            },
            DispatchTable: dispatch_table_ptr,
            RpcProtseqEndpointCount: 0,
            RpcProtseqEndpoint: ptr::null_mut(),
            DefaultManagerEpv: ptr::null_mut(),
            InterpreterInfo: ctx_ptr as *const _,
            Flags: RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
        });
        let server_if_ptr = Box::into_raw(server_if_box);

        let status = unsafe {
            RpcServerRegisterIfEx(
                server_if_ptr as *const _,
                ptr::null(),
                ptr::null(),
                RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
                RPC_C_LISTEN_MAX_CALLS_DEFAULT,
                None,
            )
        };
        if status != 0 {
            unsafe {
                let _ = RpcServerUnregisterIf(server_if_ptr as *const _, ptr::null(), 1);
                drop(Box::from_raw(ctx_ptr));
                drop(Box::from_raw(dispatch_table_ptr));
                drop(Box::from_raw(server_if_ptr));
            }
            return Err(Error::new(status, "RpcServerRegisterIfEx"));
        }

        let status = unsafe { RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, 1) };
        if status != 0 && status != RPC_S_ALREADY_LISTENING {
            unsafe {
                let _ = RpcServerUnregisterIf(server_if_ptr as *const _, ptr::null(), 1);
                drop(Box::from_raw(ctx_ptr));
                drop(Box::from_raw(dispatch_table_ptr));
                drop(Box::from_raw(server_if_ptr));
            }
            return Err(Error::new(status, "RpcServerListen"));
        }

        Ok(Self {
            server_if: server_if_ptr,
            dispatch_table: dispatch_table_ptr,
            _dispatch_entries: entries,
            ctx: ctx_ptr,
        })
    }

    pub fn stop(&self) -> Result<(), Error> {
        let status = unsafe { RpcMgmtStopServerListening(ptr::null()) };
        if status == 0 {
            Ok(())
        } else {
            Err(Error::new(status, "RpcMgmtStopServerListening"))
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        unsafe {
            let _ = RpcMgmtStopServerListening(ptr::null());
            let _ = RpcServerUnregisterIf(self.server_if as *const _, ptr::null(), 1);
            drop(Box::from_raw(self.ctx));
            drop(Box::from_raw(self.dispatch_table));
            drop(Box::from_raw(self.server_if));
        }
    }
}

pub struct Client {
    binding: *mut core::ffi::c_void,
    client_if: Box<RPC_CLIENT_INTERFACE>,
}

impl Client {
    pub fn connect(uuid: GUID, version: (u16, u16), endpoint: &str) -> Result<Self, Error> {
        let endpoint_w = wide_null(endpoint);
        let mut string_binding: PWSTR = ptr::null_mut();
        let status = unsafe {
            RpcStringBindingComposeW(
                ptr::null(),
                PROTSEQ_NCALRPC.as_ptr(),
                ptr::null(),
                endpoint_w.as_ptr(),
                ptr::null(),
                &mut string_binding,
            )
        };
        if status != 0 {
            return Err(Error::new(status, "RpcStringBindingComposeW"));
        }

        let mut binding: *mut core::ffi::c_void = ptr::null_mut();
        let status = unsafe { RpcBindingFromStringBindingW(string_binding, &mut binding) };
        unsafe {
            let _ = RpcStringFreeW(&mut string_binding);
        }
        if status != 0 {
            return Err(Error::new(status, "RpcBindingFromStringBindingW"));
        }

        let client_if = Box::new(RPC_CLIENT_INTERFACE {
            Length: mem::size_of::<RPC_CLIENT_INTERFACE>() as u32,
            InterfaceId: RPC_SYNTAX_IDENTIFIER {
                SyntaxGUID: uuid,
                SyntaxVersion: RPC_VERSION {
                    MajorVersion: version.0,
                    MinorVersion: version.1,
                },
            },
            TransferSyntax: RPC_SYNTAX_IDENTIFIER {
                SyntaxGUID: NDR_SYNTAX_GUID,
                SyntaxVersion: NDR_SYNTAX_VERSION,
            },
            DispatchTable: ptr::null_mut(),
            RpcProtseqEndpointCount: 0,
            RpcProtseqEndpoint: ptr::null_mut(),
            Reserved: 0,
            InterpreterInfo: ptr::null(),
            Flags: 0,
        });

        Ok(Self { binding, client_if })
    }

    pub fn call(&self, proc_num: u32, request: &[u8]) -> Result<Vec<u8>, Error> {
        let mut message = RPC_MESSAGE {
            Handle: self.binding,
            DataRepresentation: NDR_LOCAL_DATA_REPRESENTATION,
            Buffer: ptr::null_mut(),
            BufferLength: request.len() as u32,
            ProcNum: proc_num,
            TransferSyntax: &self.client_if.TransferSyntax as *const _ as *mut _,
            RpcInterfaceInformation: &*self.client_if as *const _ as *mut _,
            ReservedForRuntime: ptr::null_mut(),
            ManagerEpv: ptr::null_mut(),
            ImportContext: ptr::null_mut(),
            RpcFlags: 0,
        };

        let status = unsafe { I_RpcGetBuffer(&mut message) };
        if status != 0 {
            return Err(Error::new(status, "I_RpcGetBuffer"));
        }

        if !request.is_empty() {
            unsafe {
                ptr::copy_nonoverlapping(
                    request.as_ptr(),
                    message.Buffer as *mut u8,
                    request.len(),
                );
            }
        }

        let status = unsafe { I_RpcSendReceive(&mut message) };
        if status != 0 {
            unsafe {
                let _ = I_RpcFreeBuffer(&mut message);
            }
            return Err(Error::new(status, "I_RpcSendReceive"));
        }

        let response = unsafe {
            slice::from_raw_parts(message.Buffer as *const u8, message.BufferLength as usize)
                .to_vec()
        };
        unsafe {
            let _ = I_RpcFreeBuffer(&mut message);
        }
        Ok(response)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            if !self.binding.is_null() {
                let _ = RpcBindingFree(&mut self.binding);
                self.binding = ptr::null_mut();
            }
        }
    }
}
