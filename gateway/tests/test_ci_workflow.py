"""对 `.github/workflows/gateway.yml` 的纯解析测试，不起 docker、不碰 GitHub Actions。

这个文件刻意不用 harness 固件（写法参照 test_listen_table.py）：workflow 是一份 YAML，
解析结构、检查步骤顺序与字段是纯文本逻辑，秒级就能跑完，用来盯一个真实发生过的 bug——

`gateway/tests/conftest.py` 的 session 级 `harness` 固件在 `finally` 里默认执行
`compose down -v`，除非环境变量 `RMC_KEEP_ENV=1`。CI 的 "集成测试" 步骤会触发这个固件；
若它跑完时没有 `RMC_KEEP_ENV=1`，容器在该步骤结束时就被删掉了。后面的 "脚本测试"
步骤用 `docker compose exec -T gateway bats ...` 对着一个已经不存在的容器执行，19 条
bats 用例从未真的跑过；`if: failure()` 的日志导出步骤同样对着空容器，导出不出任何
日志。两个失败都不会让 CI 变红——`docker compose exec`/`docker compose logs` 对一个
不存在的服务会报错退出，但那条报错会被淹没在一堆其它输出里，很容易被读成"环境问题"
而不是"这一步压根没有测到东西"。

单靠调整 YAML 里几个步骤的先后顺序看不出这个 bug：`脚本测试` 本来就写在两条 pytest
步骤之后。真正缺的是让容器活到那一刻的 `RMC_KEEP_ENV=1`，以及跑完之后把它们清理掉的
收尾步骤——这两点也是这个文件要测的重点，不只是测顺序。
"""
from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW_PATH = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "gateway.yml"


def _load_workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def _job(workflow: dict) -> dict:
    jobs = workflow["jobs"]
    assert len(jobs) == 1, f"预期 workflow 里只有一个 job，实际有 {list(jobs)}"
    return next(iter(jobs.values()))


def _steps(job: dict) -> list[dict]:
    return job.get("steps", [])


def _step_text(step: dict) -> str:
    """把一个 step 的 name 与 run 拼成一段文本，便于用关键字定位它。"""
    return f"{step.get('name', '')}\n{step.get('run', '')}"


def _find_step_index(steps: list[dict], keyword: str) -> int:
    for i, step in enumerate(steps):
        if keyword in _step_text(step):
            return i
    raise AssertionError(f"没有找到包含 {keyword!r} 的 step；现有 step 名：" +
                          ", ".join(s.get("name", "<无名>") for s in steps))


def _effective_env(step: dict, job_env: dict) -> dict:
    """job 级 env 与 step 级 env 合并，step 级覆盖 job 级——与 GitHub Actions 的语义一致。"""
    merged = dict(job_env)
    merged.update(step.get("env") or {})
    return merged


def test_workflow_file_parses_as_yaml_with_one_job():
    """先确认文件存在、是合法 YAML、恰好一个 job，其余用例才有意义去解析结构。"""
    workflow = _load_workflow()
    assert "jobs" in workflow
    _job(workflow)  # 内部断言只有一个 job


def test_bats_step_runs_after_both_pytest_steps():
    """脚本测试（bats）必须排在"单元测试"与"集成测试"两条 pytest 步骤之后。

    这一条只盯步骤的先后顺序：谁把"脚本测试"挪到任何一条 pytest 步骤前面，
    这里就会红。顺序对不对不能证明容器在那一刻还活着——活着与否由下一条用例盯，
    两者职责不重合。
    """
    steps = _steps(_job(_load_workflow()))
    unit_idx = _find_step_index(steps, "pytest tests/test_registry.py")
    integration_idx = _find_step_index(steps, "pytest tests")
    bats_idx = _find_step_index(steps, "bats ")
    assert bats_idx > unit_idx, "脚本测试必须排在单元测试之后"
    assert bats_idx > integration_idx, "脚本测试必须排在集成测试之后"


def test_containers_are_kept_alive_through_bats_and_log_export():
    """`RMC_KEEP_ENV=1` 必须在"集成测试"跑完时、以及"脚本测试""失败时导出容器日志"
    这两步执行时都生效，否则 conftest.py 里 session 级 `harness` 固件会在"集成测试"
    步骤结束前的 `finally` 里执行 `compose down -v`，后两步对着的就是空容器。

    这条用例会因为下面任一条边而变红：
    - job 级 `env` 里根本没有 `RMC_KEEP_ENV`（brief 原始草稿就是这样）；
    - 有但值不是字符串 `"1"`（比如漏了引号被 YAML 解析成布尔 `True`，或误写成 `"0"`）；
    - `RMC_KEEP_ENV` 只写在某一步自己的 `env` 里，没覆盖到"集成测试""脚本测试"
      "失败时导出容器日志"这三步中的某一步。
    """
    workflow = _load_workflow()
    job = _job(workflow)
    job_env = job.get("env") or {}
    steps = _steps(job)
    integration_idx = _find_step_index(steps, "pytest tests")
    bats_idx = _find_step_index(steps, "bats ")
    log_idx = _find_step_index(steps, "docker compose logs")
    for idx, label in (
        (integration_idx, "集成测试"),
        (bats_idx, "脚本测试"),
        (log_idx, "失败时导出容器日志"),
    ):
        env = _effective_env(steps[idx], job_env)
        assert env.get("RMC_KEEP_ENV") == "1", (
            f"{label} 步骤看不到 RMC_KEEP_ENV=1，容器可能已经被 "
            f"session 级 harness 固件的 `compose down -v` 清理掉"
        )


def test_log_export_step_only_runs_on_failure():
    """导出容器日志的步骤必须带 `if: failure()`，否则每次成功也会白跑一次
    `docker compose logs`；这条用例会在 `if` 字段被删掉或改成别的条件时变红。
    """
    steps = _steps(_job(_load_workflow()))
    idx = _find_step_index(steps, "docker compose logs")
    assert steps[idx].get("if") == "failure()"


def test_timeout_is_at_least_30_minutes():
    """Task 6 实测反向端口回收约 80 秒，`test_zombie_port.py` 单用例预算 110 秒；
    20 分钟的原始预算连 docker build 都算不下，见方案与本任务的 R76。这条用例会在
    `timeout-minutes` 被重新调回 20（或更低）时变红。
    """
    job = _job(_load_workflow())
    assert job.get("timeout-minutes", 0) >= 30


def test_cleanup_step_always_tears_down_environment():
    """必须有一步无条件（`if: always()`）执行 `docker compose down -v`：
    `RMC_KEEP_ENV=1` 让容器活过"集成测试"步骤之后，总要有人负责收尾，
    否则 runner 上会一直留着这套 docker 环境。这条用例会在这一步被删掉、
    或者 `if` 不是 `always()`（例如漏写、或错写成 `failure()`）时变红。
    """
    steps = _steps(_job(_load_workflow()))
    idx = _find_step_index(steps, "docker compose down")
    assert steps[idx].get("if") == "always()"
