#!/usr/bin/env python3
"""Job 删除行为: 队列移除, 运行中取消, 已完成记录删除."""

import os
import sys
from collections import deque
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

with patch("main.ensure_dirs"), patch("main.init_database"), patch("main.migrate_json_to_sqlite"):
    import main  # noqa: E402


class TestDeleteJob:
    def setup_method(self) -> None:
        self._running = main.RUNNING_JOBS
        self._completed = main.COMPLETED_JOBS
        self._queue = main.JOB_QUEUE
        self._controls = main.JOB_CONTROLS
        main.RUNNING_JOBS = {}
        main.COMPLETED_JOBS = {}
        main.JOB_QUEUE = deque()
        main.JOB_CONTROLS = {}

    def teardown_method(self) -> None:
        main.RUNNING_JOBS = self._running
        main.COMPLETED_JOBS = self._completed
        main.JOB_QUEUE = self._queue
        main.JOB_CONTROLS = self._controls

    def test_delete_requires_identity(self) -> None:
        ok, message = main.delete_job("", "")
        assert ok is False
        assert "required" in message.lower()

    def test_delete_queued_job(self) -> None:
        main.RUNNING_JOBS["queued.com"] = {
            "domain": "queued.com",
            "status": "queued",
            "thread": None,
            "steps": {},
            "logs": [],
        }
        main.JOB_QUEUE.append("queued.com")
        with patch.object(main, "persist_active_jobs"):
            ok, message = main.delete_job(domain="queued.com")
        assert ok is True
        assert "queued.com" not in main.RUNNING_JOBS
        assert "queued.com" not in main.JOB_QUEUE
        assert "Deleted queued" in message

    def test_delete_running_job_requests_cancel(self) -> None:
        thread = MagicMock()
        thread.is_alive.return_value = True
        main.RUNNING_JOBS["live.com"] = {
            "domain": "live.com",
            "status": "running",
            "thread": thread,
            "steps": main.init_job_steps(False),
            "logs": [],
        }
        with patch.object(main, "persist_active_jobs"), patch.object(main, "job_log_append"):
            ok, message = main.delete_job(domain="live.com")
        assert ok is True
        assert main.JOB_CONTROLS["live.com"].is_cancel_requested() is True
        assert "deleted shortly" in message.lower() or "delete" in message.lower()

    def test_delete_completed_job(self) -> None:
        job_id = "done.com_111.2"
        main.COMPLETED_JOBS[job_id] = {"domain": "done.com", "status": "completed"}
        db = MagicMock()
        with patch.object(main, "get_db", return_value=db):
            ok, message = main.delete_job(job_id=job_id)
        assert ok is True
        assert job_id not in main.COMPLETED_JOBS
        db.execute.assert_called_once()
        assert "Deleted completed" in message

    def test_snapshot_includes_job_id(self) -> None:
        main.RUNNING_JOBS["snap.com"] = {
            "domain": "snap.com",
            "status": "running",
            "steps": {},
            "logs": [],
        }
        snapshot = main.snapshot_running_jobs()
        assert snapshot[0]["job_id"] == "snap.com"

    def test_pause_point_raises_when_cancelled(self) -> None:
        ctrl = main.JobControl()
        ctrl.request_cancel()
        main.JOB_CONTROLS["x.com"] = ctrl
        try:
            main.job_pause_point("x.com")
            assert False, "expected JobCancelled"
        except main.JobCancelled as exc:
            assert exc.domain == "x.com"
