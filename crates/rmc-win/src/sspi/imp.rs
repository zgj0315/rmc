//! SSPI 的 Win32 一侧：`AcquireCredentialsHandleW` 取当前登录用户的
//! 出站凭据，`InitializeSecurityContextW` 逐段推进协商。
//!
//! 这个模块**只做调用与缓冲区搬运**：状态码怎么解读
//! （[`super::classify_sspi_status`]）、SPN 怎么拼
//! （[`super::spn_for_proxy`]）、上下文什么时候该换新的，全都在
//! `sspi.rs` 的纯逻辑那一半，在这台 macOS 上有测试守着。这里剩下的
//! 是本机验不了的部分——`AcquireCredentialsHandleW` 与
//! `InitializeSecurityContextW` 两次调用、缓冲区的搭建与归还，只能靠
//! Windows 上的人工验收（清单由 Task 12 建，本任务的条目记在
//! task-3-report.md）。
#![allow(unsafe_code)]

use super::{SspiContext, SspiPackage, SspiStatusKind, SspiStep};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED, SEC_E_NO_AUTHENTICATING_AUTHORITY,
    SEC_E_NO_CREDENTIALS, SEC_E_OK, SEC_E_SECPKG_NOT_FOUND, SEC_E_TARGET_UNKNOWN,
    SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED, SEC_I_CONTINUE_NEEDED,
};
use windows::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleW, CompleteAuthToken, DeleteSecurityContext, FreeContextBuffer,
    FreeCredentialsHandle, InitializeSecurityContextW, SecBuffer, SecBufferDesc,
    ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONNECTION, SECBUFFER_TOKEN, SECBUFFER_VERSION,
    SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
};
use windows::Win32::Security::Credentials::SecHandle;
use zeroize::{Zeroize, Zeroizing};

// 编译期核对：`sspi.rs` 为了能在非 Windows 平台上跑表驱动测试而重新
// 声明的那四个状态码，数值必须跟 `windows` crate 里的真实定义一致。
// 两份数值一旦漂移，`classify_sspi_status` 的测试会继续全绿而线上行为
// 全错——这种分歧只在 Windows 上才现形，const 断言把它挪到了编译期。
// （Task 2 的 `winhttp.rs` 用同一手法守 `autoproxy_flags` 的常量，复审
// 实测把常量从 1 改成 9，macOS 35 passed 毫无察觉、zigbuild 直接
// error[E0080]。）
const _: () = assert!(super::SEC_STATUS_OK == SEC_E_OK.0);
const _: () = assert!(super::SEC_STATUS_CONTINUE_NEEDED == SEC_I_CONTINUE_NEEDED.0);
const _: () = assert!(super::SEC_STATUS_COMPLETE_NEEDED == SEC_I_COMPLETE_NEEDED.0);
const _: () = assert!(super::SEC_STATUS_COMPLETE_AND_CONTINUE == SEC_I_COMPLETE_AND_CONTINUE.0);
// `describe_sspi_status` 那张说明表里的六个错误码同理：hex 抄错一位
// 不会让任何测试变红，只会让诊断页显示一句错的处置建议。
const _: () = assert!(super::SEC_STATUS_TARGET_UNKNOWN == SEC_E_TARGET_UNKNOWN.0);
const _: () = assert!(super::SEC_STATUS_SECPKG_NOT_FOUND == SEC_E_SECPKG_NOT_FOUND.0);
const _: () = assert!(super::SEC_STATUS_INVALID_TOKEN == SEC_E_INVALID_TOKEN.0);
const _: () = assert!(super::SEC_STATUS_LOGON_DENIED == SEC_E_LOGON_DENIED.0);
const _: () = assert!(super::SEC_STATUS_NO_CREDENTIALS == SEC_E_NO_CREDENTIALS.0);
const _: () =
    assert!(super::SEC_STATUS_NO_AUTHENTICATING_AUTHORITY == SEC_E_NO_AUTHENTICATING_AUTHORITY.0);

/// 转成以 0 结尾的宽字符串。
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 用当前登录用户身份完成一次 Negotiate 或 NTLM 协商的安全上下文。
///
/// 不带 `Debug`：里面是两个句柄，打印出来对排查没有帮助，而"这个类型
/// 不该出现在日志里"这件事用类型本身说比用注释说更可靠。
pub struct NegotiateContext {
    package: SspiPackage,
    cred: SecHandle,
    ctx: Option<SecHandle>,
    /// SPN 的宽字符串。**必须跟着上下文一起活着**：
    /// `InitializeSecurityContextW` 只收一个指针，每一段协商都要用。
    target: Vec<u16>,
    finished: bool,
}

impl NegotiateContext {
    /// `target_spn` 形如 `HTTP/proxy.company.com`，由
    /// [`super::spn_for_proxy`] 从**代理主机名**拼出来——不是认证
    /// scheme，见那个函数的文档。
    ///
    /// 凭据不传 `pAuthData`（`None`），也就是用当前登录用户的默认凭据。
    /// 这正是这个特性存在的理由：企业代理要求 Negotiate 时，现场工程师
    /// 不需要、也不应该被要求再输一遍域口令。
    pub fn new(package: SspiPackage, target_spn: &str) -> Option<Self> {
        let package_wide = wide(package.package_name());
        let mut cred = SecHandle::default();
        let mut expiry = 0i64;
        // SAFETY: `package_wide` 是本函数栈上、以 0 结尾的宽字符串，
        // 生命周期覆盖这次调用；`cred`/`expiry` 是本次调用独占的栈上
        // 可变引用；其余参数按文档传 NULL（不指定主体、不传显式凭据、
        // 不用取密钥回调）。
        let acquired = unsafe {
            AcquireCredentialsHandleW(
                PCWSTR::null(),
                PCWSTR(package_wide.as_ptr()),
                SECPKG_CRED_OUTBOUND,
                None,
                None,
                None,
                None,
                &mut cred,
                Some(&mut expiry),
            )
        };
        if let Err(e) = acquired {
            // 只记状态码，不记任何凭据信息。
            tracing::warn!(
                "AcquireCredentialsHandleW({}) 失败：{}",
                package.package_name(),
                super::describe_sspi_status(e.code().0)
            );
            return None;
        }
        Some(Self {
            package,
            cred,
            ctx: None,
            target: wide(target_spn),
            finished: false,
        })
    }
}

/// 请求的上下文属性。
///
/// 只要 `ISC_REQ_CONNECTION`（这是面向连接的交换，不是数据报）加
/// `ISC_REQ_ALLOCATE_MEMORY`（输出 token 由 SSPI 分配）。计划原文还要
/// 了 `ISC_REQ_CONFIDENTIALITY`——这条隧道上我们从不调用
/// `EncryptMessage`/`VerifySignature`，要一个永远不会去用的服务只会
/// 缩小"哪些包与凭据能满足这次请求"的范围，没有任何收益。
const REQ_FLAGS: windows::Win32::Security::Authentication::Identity::ISC_REQ_FLAGS =
    windows::Win32::Security::Authentication::Identity::ISC_REQ_FLAGS(
        ISC_REQ_CONNECTION.0 | ISC_REQ_ALLOCATE_MEMORY.0,
    );

/// 把 SSPI 分配的输出 token 拷进一个会被抹掉的缓冲，抹掉 SSPI 那一份，
/// 再 `FreeContextBuffer` 还回去。
///
/// # Safety
/// `out.pvBuffer` 必须是 SSPI 用 `ISC_REQ_ALLOCATE_MEMORY` 分配、尚未
/// 释放的缓冲（或 NULL），且 `out.cbBuffer` 是它的真实长度；调用之后
/// 调用方不再使用这个指针。
unsafe fn take_token(out: &mut SecBuffer) -> Option<Zeroizing<Vec<u8>>> {
    if out.pvBuffer.is_null() {
        return None;
    }
    let n = out.cbBuffer as usize;
    let ptr = out.pvBuffer.cast::<u8>();
    // SAFETY: 见函数级 Safety 说明——`ptr` 指向 SSPI 分配的、长度为
    // `n` 的有效缓冲。
    let token = Zeroizing::new(unsafe { std::slice::from_raw_parts(ptr, n) }.to_vec());
    // 归还之前先抹掉 SSPI 那一份：`FreeContextBuffer` 不保证清零，这块
    // 内存会被后面的分配拿去用，而里面躺着的是域凭据的派生物。
    // `Zeroize` 用的是易失写，不会被优化掉。
    // SAFETY: 同上，这块内存在 `FreeContextBuffer` 之前仍归本调用方支配。
    unsafe { std::slice::from_raw_parts_mut(ptr, n) }.zeroize();
    // SAFETY: 同上，且之后立刻把字段置空，不会重复释放。
    unsafe {
        let _ = FreeContextBuffer(out.pvBuffer);
    }
    out.pvBuffer = std::ptr::null_mut();
    out.cbBuffer = 0;
    Some(token)
}

impl SspiContext for NegotiateContext {
    fn step(&mut self, input: Option<&[u8]>) -> SspiStep {
        if self.finished {
            return SspiStep::Failed("这个上下文的协商已经结束".into());
        }

        // 输出缓冲由 SSPI 自己分配（`ISC_REQ_ALLOCATE_MEMORY`）。不自己
        // 预分配定长缓冲：计划原文那个 16KB 固定缓冲会截断带 PAC 的
        // Kerberos token（`cbMaxToken` 在 Negotiate 上通常是 48KB），
        // 而截断之后只会换回一个 `SEC_E_BUFFER_TOO_SMALL`，没有别的提示。
        let mut out_buf = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: std::ptr::null_mut(),
        };
        let mut out_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf,
        };

        // 输入缓冲。**这段字节必须活到 Win32 调用返回为止**：计划原文
        // 把 `SecBuffer` 建在 `match` 的分支块里、让 `SecBufferDesc`
        // 记下它的地址，分支块一结束 `pBuffers` 就悬垂了——借用检查器
        // 看不见（`pBuffers` 是裸指针字段），只在 Windows 上才会现形的
        // use-after-free。这里把它放在与调用同一个作用域。
        let mut in_bytes = Zeroizing::new(input.unwrap_or_default().to_vec());
        let mut in_buf = SecBuffer {
            cbBuffer: in_bytes.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: in_bytes.as_mut_ptr().cast(),
        };
        let in_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut in_buf,
        };
        // 首段没有输入就必须传 NULL，不能传一个"长度为 0 的缓冲"。
        let pinput = input.map(|_| &in_desc as *const SecBufferDesc);

        let mut new_ctx = SecHandle::default();
        let mut attrs = 0u32;
        let mut expiry = 0i64;
        // SAFETY: `cred` 是 `new` 里拿到、本对象持有到 `Drop` 的有效
        // 凭据句柄；`self.ctx` 要么是上一段协商产出的有效上下文句柄，
        // 要么是 `None`（首段）；`self.target` 是以 0 结尾的宽字符串，
        // 活得比这次调用长；`pinput` 指向 `in_desc`，而 `in_desc` 与它
        // 指向的 `in_buf`、`in_bytes` 都在本函数栈上、生命周期覆盖这次
        // 调用；`out_desc`/`new_ctx`/`attrs`/`expiry` 都是本次调用独占的
        // 栈上可变引用。
        let status = unsafe {
            InitializeSecurityContextW(
                Some(&self.cred),
                self.ctx.as_ref().map(|c| c as *const SecHandle),
                Some(self.target.as_ptr()),
                REQ_FLAGS,
                0,
                SECURITY_NATIVE_DREP,
                pinput,
                0,
                Some(&mut new_ctx),
                Some(&mut out_desc),
                &mut attrs,
                Some(&mut expiry),
            )
        };

        // 少数包（Digest 之类）会要求补一次 `CompleteAuthToken` 才算把
        // token 做完。必须在归还输出缓冲**之前**做。
        if super::needs_complete_auth_token(status.0) {
            // SAFETY: `new_ctx` 是这次调用刚产出的上下文句柄，
            // `out_desc` 仍指向尚未归还的输出缓冲。
            if let Err(e) = unsafe { CompleteAuthToken(&new_ctx, &out_desc) } {
                tracing::warn!(
                    "CompleteAuthToken 失败：{}",
                    super::describe_sspi_status(e.code().0)
                );
            }
        }

        // 不论成败都把输出缓冲拿走并归还——失败路径下 SSPI 也可能已经
        // 写进了一段（例如要发给服务端的错误 token）。
        // SAFETY: `out_buf` 的指针要么是 NULL，要么是这次调用用
        // `ISC_REQ_ALLOCATE_MEMORY` 分配出来的缓冲。
        let token = unsafe { take_token(&mut out_buf) };

        match super::classify_sspi_status(status.0) {
            SspiStatusKind::Continue => {
                self.ctx = Some(new_ctx);
                match token {
                    Some(t) if !t.is_empty() => SspiStep::Token(t),
                    // "还要继续"却没给 token，协商推不下去了。
                    _ => {
                        self.finished = true;
                        SspiStep::Failed(format!(
                            "{} 要求继续协商却没有给出 token，状态码 0x{:08X}",
                            self.package.package_name(),
                            status.0 as u32
                        ))
                    }
                }
            }
            SspiStatusKind::Done => {
                self.ctx = Some(new_ctx);
                self.finished = true;
                match token {
                    // 最后一段 token 仍然要发出去，代理靠它放行。
                    Some(t) if !t.is_empty() => SspiStep::Token(t),
                    // 没有 token 可发了：协商到此为止。
                    _ => SspiStep::Done,
                }
            }
            SspiStatusKind::Failed => {
                // 失败时**不**接管 `new_ctx`：`InitializeSecurityContext`
                // 失败之后这个句柄的有效性没有文档保证，对一个未必有效的
                // 句柄调用 `DeleteSecurityContext` 比可能漏掉一次清理更
                // 危险；而且这条路径上这次协商已经结束，不会反复发生。
                self.finished = true;
                SspiStep::Failed(super::describe_sspi_status(status.0))
            }
        }
    }
}

impl Drop for NegotiateContext {
    fn drop(&mut self) {
        if let Some(ctx) = self.ctx.take() {
            // SAFETY: `ctx` 是本对象自己用 `InitializeSecurityContextW`
            // 建出来、且只有这一处持有所有权的上下文句柄；`take()` 保证
            // 不会对同一个句柄删两次。
            unsafe {
                let _ = DeleteSecurityContext(&ctx);
            }
        }
        // SAFETY: `cred` 是 `new` 里拿到、只有本对象持有的凭据句柄，
        // `Drop::drop` 只运行一次。
        unsafe {
            let _ = FreeCredentialsHandle(&self.cred);
        }
    }
}
