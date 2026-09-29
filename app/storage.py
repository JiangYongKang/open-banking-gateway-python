"""本地持久化存储。

每个 collection 对应 ``<data_dir>/<name>.json``（一个 JSON 对象），
并通过 ``<name>.lock`` 文件上的 ``flock`` 互斥锁 + 进程内可重入锁保证：

* 同进程多线程（FastAPI 同步端点运行在线程池）下读改写原子；
* 多进程同时运行时同样互斥；
* 写入采用临时文件 + ``os.replace``，崩溃不会留下半截 JSON。
"""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
from collections import OrderedDict
from typing import Any, Callable, Iterable


class Collection:
    """单个 JSON 文件集合的句柄，不应直接实例化，由 LocalStore 创建。"""

    def __init__(self, data_dir: str, name: str) -> None:
        self._path = os.path.join(data_dir, f"{name}.json")
        self._lock_path = os.path.join(data_dir, f"{name}.lock")
        self._thread_lock = threading.RLock()

    # ---- 底层原语：加锁 -> 读 -> mutate -> 原子写 -------------------------

    def _read_locked(self) -> dict[str, Any]:
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                return json.load(fh, object_pairs_hook=OrderedDict)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            # 文件损坏时不静默吞掉，避免覆盖仍可能有价值的数据
            raise

    def _write_locked(self, data: dict[str, Any]) -> None:
        tmp_path = self._stage_temp(data)
        os.replace(tmp_path, self._path)

    def _serialize_for_write(self, data: dict[str, Any]) -> None:
        """落盘前的序列化钩子（测试可替换以模拟磁盘故障）。"""
        return None

    def _stage_temp(self, data: dict[str, Any]) -> str:
        """把数据写到同目录临时文件并 fsync，返回临时文件路径（尚未替换正式文件）。"""
        self._serialize_for_write(data)  # 故障注入点：失败则不动任何正式文件
        directory = os.path.dirname(self._path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise
        return tmp_path

    def modify(self, fn: Callable[[dict[str, Any]], dict[str, Any] | None]) -> dict[str, Any]:
        """在独占锁内对整个集合读改写，返回更新后的集合。

        fn 直接修改入参 dict 或返回新 dict；fn 抛异常则不写入。
        """
        with self._thread_lock:
            with open(self._lock_path, "a+") as lock_fh:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
                try:
                    data = self._read_locked()
                    result = fn(data)
                    if result is not None:
                        data = result
                    self._write_locked(data)
                    return data
                finally:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    # ---- 便捷操作 --------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        return self.modify(lambda data: None).get(key, default)

    def put(self, key: str, value: Any) -> None:
        def _put(data: dict[str, Any]) -> None:
            data[key] = value

        self.modify(_put)

    def list_items(self) -> list[Any]:
        return list(self.modify(lambda data: None).values())

    def update_atomic(
        self, key: str, mutate: Callable[[Any], Any], *, factory: Callable[[], Any] | None = None
    ) -> Any:
        """对单个 key 做读改写，返回新值。key 不存在时以 factory() 为初值。"""

        def _mutate(data: dict[str, Any]) -> None:
            old = data.get(key)
            if old is None and factory is not None:
                old = factory()
            data[key] = mutate(old)

        return self.modify(_mutate)[key]

    def append_event(self, key: str, event: dict, *, factory: Callable[[], Any] | None = None) -> None:
        """向 key 对应的列表尾部追加事件，用于不可覆盖的历史记录。"""

        def _mutate(old: Any) -> list:
            if old is None and factory is not None:
                old = factory()
            if not isinstance(old, list):
                raise TypeError(f"key {key!r} 不是列表，无法追加事件")
            old.append(event)
            return old

        self.update_atomic(key, _mutate, factory=lambda: [])


class _CollectionProxy:
    """事务内对 Collection 的受限访问，操作的是快照 dict（落盘由事务统一完成）。"""

    def __init__(self, name: str, snapshot: dict[str, Any]) -> None:
        self.name = name
        self._data = snapshot

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def put(self, key: str, value: Any) -> None:
        self._data[key] = value

    def items(self) -> list[Any]:
        return list(self._data.values())

    def snapshot(self) -> dict[str, Any]:
        return self._data


class LocalStore:
    """本地 JSON 文件存储，每个名字对应一个 Collection。"""

    def __init__(self, data_dir: str) -> None:
        self._data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self._cache: dict[str, Collection] = {}
        self._cache_lock = threading.Lock()

    @property
    def data_dir(self) -> str:
        return self._data_dir

    def collection(self, name: str) -> Collection:
        with self._cache_lock:
            coll = self._cache.get(name)
            if coll is None:
                coll = Collection(self._data_dir, name)
                self._cache[name] = coll
            return coll

    def atomic(self, names: Iterable[str], fn: Callable[..., Any]) -> Any:
        """跨集合事务：按名字排序依次加锁，fn 接收同名的 _CollectionProxy。

        fn 内对 proxy 的全部修改要么全部落盘（任一写失败则整体不替换），
        保证业务状态与审计记录不会半更新。返回 fn 的返回值。
        """
        names_sorted = sorted(set(names))
        colls = [self.collection(n) for n in names_sorted]
        locks = [c._thread_lock for c in colls]
        acquired: list[Any] = []
        try:
            for lock in locks:
                lock.acquire()
                acquired.append(lock)
            lock_fhs = [open(c._lock_path, "a+") for c in colls]
            try:
                for fh in lock_fhs:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                snapshots = [c._read_locked() for c in colls]
                by_name = {
                    n: _CollectionProxy(n, s) for n, s in zip(names_sorted, snapshots)
                }
                # 加锁按名字排序（避免死锁），传参严格按调用方声明的名字顺序，
                # 与 fn 的位置参数一一对应（重复名字映射到同一代理）
                result = fn(*(by_name[n] for n in names))
                # 两阶段提交：先把所有集合序列化为临时文件（序列化/磁盘失败
                # 发生在正式文件被替换之前），全部成功后再依次原子 rename。
                stages: list[tuple[Collection, str]] = []
                for name in names_sorted:
                    coll = self.collection(name)
                    tmp_path = coll._stage_temp(by_name[name].snapshot())
                    stages.append((coll, tmp_path))
                try:
                    for coll, tmp_path in stages:
                        os.replace(tmp_path, coll._path)
                except BaseException:
                    for _, tmp_path in stages:
                        try:
                            os.unlink(tmp_path)
                        except FileNotFoundError:
                            pass
                    raise
                return result
            finally:
                for fh in lock_fhs:
                    try:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                    finally:
                        fh.close()
        finally:
            for lock in reversed(acquired):
                lock.release()

    def reset(self) -> None:
        """仅供测试：清空全部集合文件。"""
        for filename in os.listdir(self._data_dir):
            if filename.endswith(".json") or filename.endswith(".lock"):
                os.unlink(os.path.join(self._data_dir, filename))
        self._cache.clear()
