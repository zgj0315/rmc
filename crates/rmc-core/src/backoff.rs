//! 网络类错误的重连退避。序列与抖动幅度由方案 3.6 规定。
//!
//! 抖动存在的理由：同一次 Gateway 故障会同时打断一批客户端，如果大家按
//! 相同的秒数表原样重连，Gateway 恢复的那一刻会被所有客户端同时打一遍。
//! ±20% 抖动把重连时刻错开。`Jitter` 抽成 trait 是为了让测试能注入
//! `FixedJitter`——「抖动落在 0.8..=1.2 区间内」这条断言，对一个恒定返回
//! 某个界内常数的实现同样成立，所以另外用 `rand_jitter_is_not_constant`
//! 钉住「确实会变」这件事，两条互不替代。

use std::time::Duration;

/// 退避基数序列，单位秒。最后一项为封顶值，超出序列长度的尝试次数都停在
/// 这一项，不再增长。
pub const SEQUENCE_SECS: [u64; 6] = [1, 2, 5, 10, 20, 30];

/// 抖动系数来源。实现必须把返回值限制在 0.8..=1.2。
pub trait Jitter: Send + Sync {
    fn factor(&self) -> f64;
}

/// 生产用抖动，±20% 均匀分布。
pub struct RandJitter;

impl Jitter for RandJitter {
    fn factor(&self) -> f64 {
        use rand::Rng;
        rand::thread_rng().gen_range(0.8..=1.2)
    }
}

/// 测试用固定抖动：跑确定性用例时把随机性钉死成一个已知值。
pub struct FixedJitter(pub f64);

impl Jitter for FixedJitter {
    fn factor(&self) -> f64 {
        self.0.clamp(0.8, 1.2)
    }
}

/// 一条重连退避序列的状态机：记录已经发放过多少次延迟，按序列表算出
/// 下一次该等多久。
pub struct Backoff {
    attempt: u32,
    jitter: Box<dyn Jitter>,
}

impl Backoff {
    pub fn new(jitter: Box<dyn Jitter>) -> Self {
        Self { attempt: 0, jitter }
    }

    /// 已经发放过的延迟个数，界面上显示为“第 n 次重连”。
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// 算出下一次该等待的时长，并把发放计数加一。超过序列长度后一直
    /// 停在最后一项（封顶值），不会继续增长、也不会回绕。
    pub fn next_delay(&mut self) -> Duration {
        let index = (self.attempt as usize).min(SEQUENCE_SECS.len() - 1);
        let base = SEQUENCE_SECS[index] as f64;
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_secs_f64(base * self.jitter.factor())
    }

    /// 收到网络变化或休眠恢复事件、或一次连接成功后调用，回到序列起点。
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn no_jitter() -> Box<dyn Jitter> {
        Box::new(FixedJitter(1.0))
    }

    #[test]
    fn follows_the_documented_sequence_then_caps_at_30s() {
        let mut b = Backoff::new(no_jitter());
        let got: Vec<u64> = (0..9).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(got, vec![1, 2, 5, 10, 20, 30, 30, 30, 30]);
    }

    #[test]
    fn attempt_counts_delays_handed_out() {
        let mut b = Backoff::new(no_jitter());
        assert_eq!(b.attempt(), 0);
        b.next_delay();
        assert_eq!(b.attempt(), 1);
        b.next_delay();
        assert_eq!(b.attempt(), 2);
    }

    #[test]
    fn reset_returns_to_the_first_delay() {
        let mut b = Backoff::new(no_jitter());
        for _ in 0..5 {
            b.next_delay();
        }
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn jitter_scales_the_base_delay() {
        let mut low = Backoff::new(Box::new(FixedJitter(0.8)));
        let mut high = Backoff::new(Box::new(FixedJitter(1.2)));
        for _ in 0..2 {
            low.next_delay();
            high.next_delay();
        }
        // 第三个延迟基数 5 秒
        assert_eq!(low.next_delay(), Duration::from_millis(4000));
        assert_eq!(high.next_delay(), Duration::from_millis(6000));
    }

    #[test]
    fn rand_jitter_stays_within_twenty_percent() {
        let j = RandJitter;
        for _ in 0..1000 {
            let f = j.factor();
            assert!((0.8..=1.2).contains(&f), "抖动系数越界：{f}");
        }
    }

    #[test]
    fn rand_jitter_is_not_constant() {
        let j = RandJitter;
        let first = j.factor();
        assert!((0..100).any(|_| j.factor() != first), "抖动没有随机性");
    }

    #[test]
    fn delay_never_below_800ms_or_above_36s() {
        let mut b = Backoff::new(Box::new(RandJitter));
        for _ in 0..50 {
            let d = b.next_delay();
            assert!(d >= Duration::from_millis(800), "{d:?}");
            assert!(d <= Duration::from_millis(36_000), "{d:?}");
        }
    }
}
