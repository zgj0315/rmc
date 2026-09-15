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

use super::{SspiContext, SspiPackage, SspiStep};
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

/// 用一段输入字节搭出 `SecBufferDesc`，在**这个函数自己的栈帧上**，
/// 然后把指向它的指针交给 `f`。
///
/// # 这个形状是干什么用的（W34）
///
/// 计划原文把 `SecBuffer` 建在 `match` 的分支块里、让 `SecBufferDesc`
/// 记下它的地址，分支块一结束 `pBuffers` 就悬垂了——
/// `InitializeSecurityContextW` 调用时读的是一段已经还给栈的内存。
/// 那是本计划至今最严重的一处缺陷，而**三条自动化防线对它全部双盲**：
/// 借用检查器看不见（`pBuffers` 是 `*mut SecBuffer`，`&mut buf` 在结构
/// 体字段初始化的位置隐式强转，借用当场就结束了）；
/// `cargo zigbuild --tests` 绿、零告警；`clippy -- -D warnings` 绿、
/// 零告警；macOS 上整块 `#[cfg(windows)]` 被切掉，62 条测试一行都跑
/// 不到。复审在仓库外的副本里忠实还原过原写法，逐条实测确认。
///
/// 第一版的修法是"把缓冲放到与调用同一个作用域"，对是对的，但**防复发
/// 只有一条注释**——类型上没有任何东西挡住后人再把它挪回块里。改成闭包
/// 之后，那对自引用的结构体被关进一个必然比 `f(...)` 长寿的栈帧，调用
/// 方连"建在块里"这个形状都写不出来。
///
/// 另一条语义一并被类型吃掉了：**首段没有输入就必须传 NULL，不能传一个
/// "长度为 0 的缓冲"**。这里用"`bytes` 空 ⇒ 交 `None`"表达——零长输入
/// 缓冲对 SSPI 从来就不是一个合法输入，于是它也变成了写不出来的形状。
fn with_input_desc<R>(bytes: &mut [u8], f: impl FnOnce(Option<*const SecBufferDesc>) -> R) -> R {
    if bytes.is_empty() {
        return f(None);
    }
    let mut buf = SecBuffer {
        cbBuffer: bytes.len() as u32,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: bytes.as_mut_ptr().cast(),
    };
    let desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut buf,
    };
    // `buf` 与 `desc` 都是本函数的局部变量，它们的存储活到本函数返回
    // 为止——也就是必然覆盖下面这次 `f` 调用。
    f(Some(&desc as *const SecBufferDesc))
}

/// 用一个**由 SSPI 分配**的输出缓冲搭出 `SecBufferDesc`，同样建在
/// **这个函数自己的栈帧上**，把指向它的指针交给 `f`；`f` 返回之后，
/// 不论成败都把 SSPI 写进去的 token 取走、抹零、`FreeContextBuffer`
/// 还回去。
///
/// # 为什么输出侧也要收成这个形状（W44）
///
/// [`with_input_desc`] 只收了输入那一半。输出那一半
/// （`out_desc.pBuffers = &mut out_buf`，两个都是 `step` 的局部变量，
/// 而 `out_desc` 要活过闭包里那次 `InitializeSecurityContextW`）是
/// **一模一样的自引用形状**，一旦有人把 `out_buf` 挪进一个块里就是同
/// 一个 use-after-free——而复审实测过：这么改之后 macOS 74 条测试
/// `ok`、`cargo zigbuild --tests` rc=0 零告警、`clippy -- -D warnings`
/// rc=0 零告警，**三道防线同样全盲**。那块缓冲里装的正是刚从 SSPI
/// 拿到的 token。
///
/// 收进闭包之后，`buf` 与 `desc` 被关进一个必然比 `f(...)` 长寿的栈帧，
/// 调用方连"建在块里"这个形状都写不出来。
///
/// 顺带把两条顺序约束也变成结构性的：
///
/// 1. **归还一定发生**——不论 `f` 返回的是成功还是失败状态码，
///    `take_token` 都在 `f` 返回之后执行。`ISC_REQ_ALLOCATE_MEMORY`
///    下缓冲是 SSPI 分配的，必须 `FreeContextBuffer`，而**失败路径上
///    SSPI 也可能已经写进了一段**（例如要发给服务端的错误 token），
///    所以"失败就直接 return"是漏。
///
///    唯一的例外是 `f` 内部 panic 展开：那时 `take_token` 不执行，
///    缓冲既不抹零也不归还。`f` 里眼下唯一可能 panic 的是
///    `tracing::warn!`，实际到不了；真要说死得套一个 drop guard。
/// 2. **`CompleteAuthToken` 一定排在归还之前**——它要读的就是这块还
///    没还回去的缓冲，所以它只能写在 `f` 内部。
///
/// # Safety
///
/// `f` 拿到的那个指针只许交给带 `ISC_REQ_ALLOCATE_MEMORY` 的
/// `InitializeSecurityContextW`（本模块的 [`REQ_FLAGS`] 固定带着它）
/// 与紧随其后、针对同一次调用的 `CompleteAuthToken`；不许往
/// `pvBuffer` 里塞一个不是 SSPI 分配的指针，也不许把这个指针留到 `f`
/// 返回之后。归还那一步（[`take_token`] 里的 `FreeContextBuffer`）
/// 就建立在"这块缓冲只可能是 SSPI 分配的"这一条上。
unsafe fn with_output_desc<R>(
    f: impl FnOnce(*mut SecBufferDesc) -> R,
) -> (R, Option<Zeroizing<Vec<u8>>>) {
    // 不自己预分配定长缓冲：计划原文那个 16KB 固定缓冲会截断带 PAC 的
    // Kerberos token（`cbMaxToken` 在 Negotiate 上通常是 48KB），而
    // 截断之后只会换回一个 `SEC_E_BUFFER_TOO_SMALL`，没有别的提示。
    let mut buf = SecBuffer {
        cbBuffer: 0,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: std::ptr::null_mut(),
    };
    let mut desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut buf,
    };
    // `buf` 与 `desc` 都是本函数的局部变量，它们的存储活到本函数返回
    // 为止——也就是必然覆盖下面这次 `f` 调用。
    let out = f(&mut desc);
    // SAFETY: 按函数级 Safety 契约，`f` 只可能让 SSPI 往 `buf` 里写一块
    // 自己分配的缓冲（或者一个字节都没写，那时 `pvBuffer` 仍是 NULL）。
    let token = unsafe { take_token(&mut buf) };
    (out, token)
}

impl SspiContext for NegotiateContext {
    fn step(&mut self, input: Option<&[u8]>) -> SspiStep {
        // 这一支经 [`super::SspiProxyAuthenticator`] **到不了**（W46）：
        // 会把 `finished` 置真的三种结局里，`Done` 与 `Failed` 都让协商器
        // 当场 `neg.context = None`，而 `Token { last: true }` 让协商器记下
        // `concluded`、下一次调用在 `advance` 里就被 `Completed` 那一支拦
        // 住，根本不会再碰这个上下文。留着它是因为 [`NegotiateContext`] 是
        // 一个**公开类型**、实现的是一个公开 trait：任何别的调用方都可以
        // 自己驱动它，而对一个已经收工的 SSPI 上下文再调一次
        // `InitializeSecurityContextW` 换回来的是一个看不懂的状态码。
        // 文案因此写成给人看的话，不再是那句内部行话。
        if self.finished {
            return SspiStep::Failed(format!(
                "{} 协商在这个上下文里已经走完，不能再往前推进；下一次连接需要一个新的上下文",
                self.package.package_name()
            ));
        }

        // 输入缓冲。首段没有输入 → 空切片 → `with_input_desc` 交 NULL。
        // 那个 helper 的文档解释了为什么这里必须是闭包形状（W34）。
        let mut in_bytes = Zeroizing::new(input.unwrap_or_default().to_vec());

        let mut new_ctx = SecHandle::default();
        let mut attrs = 0u32;
        let mut expiry = 0i64;

        // 输出缓冲同样收进闭包（W44）：`with_output_desc` 的栈帧覆盖整个
        // 调用，缓冲的归还与 `CompleteAuthToken` 的先后也一并由它保证。
        //
        // 闭包单独绑一个名字，而不是写在 `unsafe { ... }` 里面：那样整个
        // 闭包体都会落进同一个 `unsafe` 块，里面每一处 FFI 调用各自的
        // SAFETY 注释就都变成 `unused_unsafe` 告警，这个模块最需要的
        // 「一处 unsafe 一条理由」也就没了地方写。
        let call = |pout: *mut SecBufferDesc| {
            with_input_desc(&mut in_bytes, |pinput| {
                // SAFETY: `cred` 是 `new` 里拿到、本对象持有到 `Drop`
                // 的有效凭据句柄；`self.ctx` 要么是上一段协商产出的
                // 有效上下文句柄，要么是 `None`（首段）；`self.target`
                // 是以 0 结尾的宽字符串，活得比这次调用长；`pinput`
                // 要么是 NULL，要么指向 `with_input_desc` 栈帧上的
                // `SecBufferDesc`——那个栈帧覆盖整个闭包调用，而它指
                // 向的 `in_bytes` 是本函数的局部变量；`pout` 指向
                // `with_output_desc` 栈帧上的 `SecBufferDesc`，那个栈
                // 帧同样覆盖整个闭包调用；`new_ctx`/`attrs`/`expiry`
                // 都是本次调用独占的栈上可变引用。
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
                        Some(pout),
                        &mut attrs,
                        Some(&mut expiry),
                    )
                };

                // 少数包（Digest 之类）会要求补一次 `CompleteAuthToken`
                // 才算把 token 做完。**必须在归还输出缓冲之前做**——
                // 写在这里，这条顺序就是结构性的：归还发生在
                // `with_output_desc` 里、本闭包返回之后。
                if super::needs_complete_auth_token(status.0) {
                    // SAFETY: `new_ctx` 是这次调用刚产出的上下文句柄，
                    // `pout` 仍指向尚未归还的输出缓冲。
                    if let Err(e) = unsafe { CompleteAuthToken(&new_ctx, pout) } {
                        tracing::warn!(
                            "CompleteAuthToken 失败：{}",
                            super::describe_sspi_status(e.code().0)
                        );
                    }
                }
                status
            })
        };
        // SAFETY: 上面那个闭包只把 `pout` 交给带 `ISC_REQ_ALLOCATE_MEMORY`
        // 的 `InitializeSecurityContextW`（[`REQ_FLAGS`] 固定带着它）与紧
        // 随其后、针对同一次调用的 `CompleteAuthToken`，不另作他用，也不
        // 把它留到闭包之外——这正是 `with_output_desc` 的 Safety 契约。
        let (status, token) = unsafe { with_output_desc(call) };

        // 状态码 + 输出 token → 这一段算什么、句柄接不接管、上下文到没
        // 到头。**判断本身一行都不留在这里**（W29）：全在
        // `super::step_from` 那个纯函数里，在 macOS 上有表驱动测试守着。
        // 这 35 行原本就在这个 `match` 里，而复审实测过：把 `Continue`
        // 与 `Done` 两条 arm 的函数体对调，zigbuild、clippy、62 条测试
        // 全绿、零告警。
        let decision = super::step_from(
            super::classify_sspi_status(status.0),
            token,
            self.package,
            status.0,
        );
        if decision.adopt_context {
            self.ctx = Some(new_ctx);
        }
        self.finished = decision.finished;
        decision.step
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
