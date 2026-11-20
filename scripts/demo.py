#!/usr/bin/env python3
"""对运行中的服务依次触发全部演示场景，可在页面上实时观察。

用法：python scripts/demo.py [--base http://127.0.0.1:8000]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request

SCENARIOS = [
    ("ordered", "按序投递 5 笔 → 全部应用，水位推进"),
    ("duplicate", "同一签名投递重放 → 第二次被去重"),
    ("out_of_order", "乱序到达 → 暂存，补齐缺口后按序释放"),
    ("delayed_stale", "水位已过的迟到事件 → 拒绝（stale）"),
    ("key_rotation", "轮换密钥 → 旧密钥窗口内可用、新密钥正常"),
    ("expired_old_key", "结束双密钥窗口 → 旧密钥签名被拒"),
    ("bad_signature", "伪造密钥签名 → 拒绝"),
    ("replay_old_timestamp", "过期时间戳重放 → 拒绝"),
    ("partial_failure", "批中一笔瞬时失败 → 水位停住、后续暂存"),
]


def post(base: str, path: str) -> dict:
    req = urllib.request.Request(base + path, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    print("== 重置环境 ==")
    post(args.base, "/admin/reset")

    for name, desc in SCENARIOS:
        print(f"\n== 场景 {name}: {desc}")
        result = post(args.base, f"/admin/demo/{name}")
        if not result.get("ok"):
            print(f"   失败: {result.get('detail')}")
            continue
        for step in result["steps"]:
            print(f"   seq={step.get('seq')!s:>4}  outcome={step['outcome']:<24} "
                  f"key={step.get('key_role') or '-':<8} {step['detail']}")
        time.sleep(0.3)

    print("\n== 部分失败场景：重试失败事件 ==")
    state = json.loads(urllib.request.urlopen(args.base + "/api/state").read())
    for ev in state["failed"]:
        path = f"/admin/events/{ev['event_id']}/{ev['version']}/retry"
        result = post(args.base, path)
        print(f"   重试 {ev['event_id']} v{ev['version']}: "
              f"{'成功' if result.get('ok') else '仍失败'}，水位={result.get('watermark')}")

    state = json.loads(urllib.request.urlopen(args.base + "/api/state").read())
    print(f"\n最终状态：水位={state['watermark']}  计数={state['counts']}")
    print(f"打开 {args.base}/ 查看监控页。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
