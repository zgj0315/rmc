//! 认证失败限流与未认证连接限额。纯逻辑，时间由调用方传入，测试不用真等
//! （生产侧用 `std::time::Instant::now()` 就行——`Throttle` 本身不摸真实时钟）。
//!
//! **不做按账号锁定**（spec §6）：只按来源 IP 记失败次数、封禁来源 IP。
//! 按账号锁定等于给攻击者一个免费的拒绝服务开关——随便报一个存在的账号名、
//! 故意认证失败几次，就能把合法账号的登录能力锁死，代价比"猜中口令"低得多。
//! 按来源限流不会有这个问题：攻击者锁的是自己的来源地址，锁不到别人。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Limits {
    pub per_ip_failures: u32,
    pub window: Duration,
    pub ban: Duration,
    pub max_unauth_global: usize,
    pub max_unauth_per_ip: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_ip_failures: 10,
            window: Duration::from_secs(600),
            ban: Duration::from_secs(900),
            max_unauth_global: 64,
            max_unauth_per_ip: 8,
        }
    }
}

impl Limits {
    /// 测试用：数值缩小，行为不变。
    pub fn tiny() -> Self {
        Self {
            per_ip_failures: 3,
            window: Duration::from_secs(2),
            ban: Duration::from_secs(2),
            max_unauth_global: 4,
            max_unauth_per_ip: 2,
        }
    }
}

#[derive(Default)]
struct State {
    failures: HashMap<IpAddr, VecDeque<Instant>>,
    banned_until: HashMap<IpAddr, Instant>,
    unauth_global: usize,
    unauth_per_ip: HashMap<IpAddr, usize>,
}

pub struct Throttle {
    limits: Limits,
    state: Arc<Mutex<State>>,
}

pub enum Admit {
    Ok(UnauthSlot),
    Banned,
    TooMany,
}

/// 一个未认证连接占的名额。`drop` 或 `release()` 都归还，二者只会生效一次。
pub struct UnauthSlot {
    state: Arc<Mutex<State>>,
    ip: IpAddr,
    live: bool,
}

impl UnauthSlot {
    pub fn release(mut self) {
        self.give_back();
    }

    fn give_back(&mut self) {
        if !self.live {
            return;
        }
        self.live = false;
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.unauth_global = s.unauth_global.saturating_sub(1);
        if let Some(n) = s.unauth_per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                s.unauth_per_ip.remove(&self.ip);
            }
        }
    }
}

impl Drop for UnauthSlot {
    fn drop(&mut self) {
        self.give_back();
    }
}

impl Throttle {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    pub fn is_banned(&self, ip: IpAddr, now: Instant) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match s.banned_until.get(&ip) {
            Some(until) if *until > now => true,
            Some(_) => {
                s.banned_until.remove(&ip);
                false
            }
            None => false,
        }
    }

    pub fn admit(&self, ip: IpAddr, now: Instant) -> Admit {
        if self.is_banned(ip, now) {
            return Admit::Banned;
        }
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let per_ip = *s.unauth_per_ip.get(&ip).unwrap_or(&0);
        if s.unauth_global >= self.limits.max_unauth_global
            || per_ip >= self.limits.max_unauth_per_ip
        {
            return Admit::TooMany;
        }
        s.unauth_global += 1;
        *s.unauth_per_ip.entry(ip).or_insert(0) += 1;
        Admit::Ok(UnauthSlot {
            state: self.state.clone(),
            ip,
            live: true,
        })
    }

    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let q = s.failures.entry(ip).or_default();
        q.push_back(now);
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > self.limits.window)
        {
            q.pop_front();
        }
        if q.len() as u32 >= self.limits.per_ip_failures {
            q.clear();
            s.banned_until.insert(ip, now + self.limits.ban);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::{Duration, Instant};
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// 改红：`record_failure` 里把 `>= per_ip_failures` 改成 `>`。
    #[test]
    fn n_failures_in_the_window_ban_the_source_and_the_ban_expires() {
        let t = Throttle::new(Limits::tiny()); // 3 次 / 2s 窗口 / 2s 封禁
        let t0 = Instant::now();
        for _ in 0..2 {
            t.record_failure(ip("1.1.1.1"), t0);
        }
        assert!(!t.is_banned(ip("1.1.1.1"), t0));
        t.record_failure(ip("1.1.1.1"), t0);
        assert!(t.is_banned(ip("1.1.1.1"), t0 + Duration::from_millis(100)));
        assert!(matches!(
            t.admit(ip("1.1.1.1"), t0 + Duration::from_millis(100)),
            Admit::Banned
        ));
        assert!(
            !t.is_banned(ip("1.1.1.1"), t0 + Duration::from_millis(2100)),
            "封禁到期"
        );
        assert!(!t.is_banned(ip("2.2.2.2"), t0), "别的来源不受影响");
    }

    #[test]
    fn failures_outside_the_window_do_not_count() {
        let t = Throttle::new(Limits::tiny());
        let t0 = Instant::now();
        t.record_failure(ip("1.1.1.1"), t0);
        t.record_failure(ip("1.1.1.1"), t0 + Duration::from_millis(500));
        // 第三次在窗口外：前两次已经滑出去了
        t.record_failure(ip("1.1.1.1"), t0 + Duration::from_millis(2600));
        assert!(!t.is_banned(ip("1.1.1.1"), t0 + Duration::from_millis(2600)));
    }

    /// 改红：`UnauthSlot::drop` 里不减计数——第三格红。
    ///
    /// **实测记录，brief 字面代码有一处真实 bug，已按 GLOBAL.md 的处置
    /// 原则改写并如实记录**：brief 原文在"释放后能再进"这一句只写
    /// `assert!(matches!(t.admit(...), Admit::Ok(_)), "释放后能再进");`，
    /// 没有把 `admit` 返回的 `UnauthSlot` 绑到变量上——它是一个临时值，
    /// `matches!` 宏只借用它做一次模式匹配，这个临时值在整条 `assert!`
    /// 语句结束时就被 `drop`，根本没有持续占着 1.1.1.1 的第二个名额。
    /// 照字面跑（先于本文件其余改动单独验证过）：走到下面"全局上限"那句
    /// 断言时，真实占用只有 `a2`（1.1.1.1）+ `b1`/`b2`（2.2.2.2）三条，
    /// 不是注释写的四条，`admit(3.3.3.3, ...)` 因为全局 3 < 4 直接
    /// `Admit::Ok`，`assert!(..., Admit::TooMany)` 在这一步真的 panic——
    /// 不是"改红能不能打红"的问题，是这条测试字面照抄根本跑不绿。
    /// 修法：把这次 `admit` 的结果绑到 `a3`，让它像 `a2`/`b1`/`b2` 一样
    /// 活到"全局上限"那句断言，凑够四条在线名额，跟注释描述的场景对上。
    #[test]
    fn unauthenticated_slots_are_capped_and_released_on_drop() {
        let t = Throttle::new(Limits::tiny()); // 全局 4，每 IP 2
        let now = Instant::now();
        let a1 = t.admit(ip("1.1.1.1"), now);
        let a2 = t.admit(ip("1.1.1.1"), now);
        assert!(matches!(a1, Admit::Ok(_)) && matches!(a2, Admit::Ok(_)));
        assert!(
            matches!(t.admit(ip("1.1.1.1"), now), Admit::TooMany),
            "每 IP 上限"
        );
        drop(a1);
        // 绑到 `a3`，让这个名额活到下面"全局上限"那句断言——不绑变量的话
        // 它是个临时值，这条语句结束就被 drop，根本占不住名额（见上面的
        // 实测记录）。
        let a3 = t.admit(ip("1.1.1.1"), now);
        assert!(matches!(a3, Admit::Ok(_)), "释放后能再进");
        let b1 = t.admit(ip("2.2.2.2"), now);
        let b2 = t.admit(ip("2.2.2.2"), now);
        assert!(matches!(b1, Admit::Ok(_)) && matches!(b2, Admit::Ok(_)));
        // 此时全局已 4（1.1.1.1：a2 + a3 两条 + 2.2.2.2：b1 + b2 两条），
        // 第三个来源也进不来
        assert!(
            matches!(t.admit(ip("3.3.3.3"), now), Admit::TooMany),
            "全局上限"
        );
        // 认证通过后显式 release：不再占未认证名额
        if let Admit::Ok(slot) = b2 {
            slot.release();
        }
        assert!(matches!(t.admit(ip("3.3.3.3"), now), Admit::Ok(_)));
    }
}
