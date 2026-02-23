from __future__ import annotations

import ctypes
import logging
import os
import threading
import uuid
from dataclasses import dataclass
from time import monotonic
from typing import Any


logger = logging.getLogger(__name__)


ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
ERROR_SUCCESS = 0
ERROR_NOT_FOUND = 1168

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_FLAG_PROCESS = 0x00000001
INVALID_PROCESSTRACE_HANDLE = ctypes.c_uint64(-1).value


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def _guid_from_string(value: str) -> GUID:
    u = uuid.UUID(value)
    data4 = (ctypes.c_ubyte * 8).from_buffer_copy(u.bytes[8:16])
    return GUID(u.fields[0], u.fields[1], u.fields[2], data4)


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", ctypes.c_uint32),
        ("ProviderId", ctypes.c_uint32),
        ("HistoricalContext", ctypes.c_uint64),
        ("TimeStamp", ctypes.c_int64),
        ("Guid", GUID),
        ("ClientContext", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
    ]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", ctypes.c_uint32),
        ("MinimumBuffers", ctypes.c_uint32),
        ("MaximumBuffers", ctypes.c_uint32),
        ("MaximumFileSize", ctypes.c_uint32),
        ("LogFileMode", ctypes.c_uint32),
        ("FlushTimer", ctypes.c_uint32),
        ("EnableFlags", ctypes.c_uint32),
        ("AgeLimit", ctypes.c_int32),
        ("NumberOfBuffers", ctypes.c_uint32),
        ("FreeBuffers", ctypes.c_uint32),
        ("EventsLost", ctypes.c_uint32),
        ("BuffersWritten", ctypes.c_uint32),
        ("LogBuffersLost", ctypes.c_uint32),
        ("RealTimeBuffersLost", ctypes.c_uint32),
        ("LoggerThreadId", ctypes.c_uint64),
        ("LogFileNameOffset", ctypes.c_uint32),
        ("LoggerNameOffset", ctypes.c_uint32),
    ]


class ENABLE_TRACE_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ("Version", ctypes.c_uint32),
        ("EnableProperty", ctypes.c_uint32),
        ("ControlFlags", ctypes.c_uint32),
        ("SourceId", GUID),
        ("EnableFilterDesc", ctypes.c_void_p),
        ("FilterDescCount", ctypes.c_uint32),
    ]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Id", ctypes.c_uint16),
        ("Version", ctypes.c_ubyte),
        ("Channel", ctypes.c_ubyte),
        ("Level", ctypes.c_ubyte),
        ("Opcode", ctypes.c_ubyte),
        ("Task", ctypes.c_uint16),
        ("Keyword", ctypes.c_uint64),
    ]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint16),
        ("HeaderType", ctypes.c_uint16),
        ("Flags", ctypes.c_uint16),
        ("EventProperty", ctypes.c_uint16),
        ("ThreadId", ctypes.c_uint32),
        ("ProcessId", ctypes.c_uint32),
        ("TimeStamp", ctypes.c_int64),
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("KernelTime", ctypes.c_uint32),
        ("UserTime", ctypes.c_uint32),
        ("ActivityId", GUID),
    ]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ProcessorNumber", ctypes.c_ubyte),
        ("Alignment", ctypes.c_ubyte),
        ("LoggerId", ctypes.c_uint16),
    ]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", ctypes.c_uint16),
        ("UserDataLength", ctypes.c_uint16),
        ("ExtendedData", ctypes.c_void_p),
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p),
    ]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", ctypes.c_uint16),
        ("wMonth", ctypes.c_uint16),
        ("wDayOfWeek", ctypes.c_uint16),
        ("wDay", ctypes.c_uint16),
        ("wHour", ctypes.c_uint16),
        ("wMinute", ctypes.c_uint16),
        ("wSecond", ctypes.c_uint16),
        ("wMilliseconds", ctypes.c_uint16),
    ]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Bias", ctypes.c_int32),
        ("StandardName", ctypes.c_wchar * 32),
        ("StandardDate", SYSTEMTIME),
        ("StandardBias", ctypes.c_int32),
        ("DaylightName", ctypes.c_wchar * 32),
        ("DaylightDate", SYSTEMTIME),
        ("DaylightBias", ctypes.c_int32),
    ]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", ctypes.c_uint32),
        ("Version", ctypes.c_uint32),
        ("ProviderVersion", ctypes.c_uint32),
        ("NumberOfProcessors", ctypes.c_uint32),
        ("EndTime", ctypes.c_int64),
        ("TimerResolution", ctypes.c_uint32),
        ("MaximumFileSize", ctypes.c_uint32),
        ("LogFileMode", ctypes.c_uint32),
        ("BuffersWritten", ctypes.c_uint32),
        ("StartBuffers", ctypes.c_uint32),
        ("PointerSize", ctypes.c_uint32),
        ("EventsLost", ctypes.c_uint32),
        ("CpuSpeedInMHz", ctypes.c_uint32),
        ("LoggerName", ctypes.c_wchar_p),
        ("LogFileName", ctypes.c_wchar_p),
        ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", ctypes.c_int64),
        ("PerfFreq", ctypes.c_int64),
        ("StartTime", ctypes.c_int64),
        ("ReservedFlags", ctypes.c_uint32),
        ("BuffersLost", ctypes.c_uint32),
    ]


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [
        ("LogFileName", ctypes.c_wchar_p),
        ("LoggerName", ctypes.c_wchar_p),
        ("CurrentTime", ctypes.c_int64),
        ("BuffersRead", ctypes.c_uint32),
        ("ProcessTraceMode", ctypes.c_uint32),
        ("CurrentEvent", ctypes.c_byte * 80),
        ("LogfileHeader", TRACE_LOGFILE_HEADER),
        ("BufferCallback", ctypes.c_void_p),
        ("BufferSize", ctypes.c_uint32),
        ("Filled", ctypes.c_uint32),
        ("EventsLost", ctypes.c_uint32),
        ("EventRecordCallback", ctypes.c_void_p),
        ("IsKernelTrace", ctypes.c_uint32),
        ("Context", ctypes.c_void_p),
    ]


class PROPERTY_DATA_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("PropertyName", ctypes.c_uint64),
        ("ArrayIndex", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


@dataclass(frozen=True)
class ProcessWatcherStatus:
    available: bool
    permission_denied: bool
    reason: str = ""


def _parse_int(value: str | None) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return 0


def _is_process_start_event(event_id: int, opcode: int) -> bool:
    # Kernel process-start events should match known process event ids
    # and start opcode at the same time.
    return event_id in {0, 1} and opcode == 1


class EtwProcessWatcher:
    """Real-time ETW kernel process-start watcher."""

    def __init__(self, on_process_start):
        self._on_process_start = on_process_start
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._trace_handle = ctypes.c_uint64(0)
        self._session_handle = ctypes.c_uint64(0)
        self._session_name = ""
        self._session_started_by_us = False
        self._last_error = 0
        self._callback_fn = None
        self._session_props_buf = None
        self._status = ProcessWatcherStatus(available=False, permission_denied=False, reason="not_started")
        self._loop_error_count = 0
        self._callback_error_count = 0
        self._close_error_count = 0
        self._stop_error_count = 0

    def _log_failure(self, phase: str, error: Exception, count: int) -> None:
        if count == 1:
            logger.warning("ETW %s failed (first): %s", phase, error)
        elif count % 25 == 0:
            logger.warning("ETW %s failures=%d latest=%s", phase, count, error)

    @property
    def status(self) -> ProcessWatcherStatus:
        return self._status

    def start(self) -> ProcessWatcherStatus:
        if ctypes.windll is None:
            self._status = ProcessWatcherStatus(available=False, permission_denied=False, reason="unsupported")
            return self._status

        if self._thread is not None:
            return self._status

        ok, err = self._start_realtime_trace()
        if not ok:
            denied = int(err) == ERROR_ACCESS_DENIED
            reason = f"access_denied:{err}" if denied else f"etw_start_failed:{err}"
            self._status = ProcessWatcherStatus(available=False, permission_denied=denied, reason=reason)
            self._last_error = int(err)
            return self._status

        self._status = ProcessWatcherStatus(available=True, permission_denied=False, reason="ok")
        self._thread = threading.Thread(target=self._run_process_trace, name="etw-process-watcher", daemon=True)
        self._thread.start()
        return self._status

    def stop(self) -> None:
        self._stop_event.set()
        self._close_trace()
        self._stop_session()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._thread = None

    def _run_process_trace(self) -> None:
        if not self._trace_handle.value:
            return
        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            ProcessTrace = advapi32.ProcessTrace
            ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
            ProcessTrace.restype = ctypes.c_uint32

            handle_arr = (ctypes.c_uint64 * 1)(self._trace_handle.value)
            _ = ProcessTrace(handle_arr, 1, None, None)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
            self._loop_error_count += 1
            self._log_failure("process_trace", exc, self._loop_error_count)
            logger.debug("ETW ProcessTrace loop failed", exc_info=True)

    def _start_realtime_trace(self) -> tuple[bool, int]:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        tdh = ctypes.WinDLL("tdh", use_last_error=True)

        StartTraceW = advapi32.StartTraceW
        StartTraceW.argtypes = [
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_wchar_p,
            ctypes.POINTER(EVENT_TRACE_PROPERTIES),
        ]
        StartTraceW.restype = ctypes.c_uint32

        OpenTraceW = advapi32.OpenTraceW
        OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
        OpenTraceW.restype = ctypes.c_uint64

        TdhGetPropertySize = tdh.TdhGetPropertySize
        TdhGetPropertySize.argtypes = [
            ctypes.POINTER(EVENT_RECORD),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(PROPERTY_DATA_DESCRIPTOR),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        TdhGetPropertySize.restype = ctypes.c_uint32

        TdhGetProperty = tdh.TdhGetProperty
        TdhGetProperty.argtypes = [
            ctypes.POINTER(EVENT_RECORD),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(PROPERTY_DATA_DESCRIPTOR),
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        TdhGetProperty.restype = ctypes.c_uint32

        EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))

        kernel_logger_name = "NT Kernel Logger"
        system_trace_control_guid = _guid_from_string("9e814aad-3204-11d2-9a82-006008a86939")
        session_name = kernel_logger_name
        self._session_name = session_name

        name_buf_bytes = (len(session_name) + 1) * ctypes.sizeof(ctypes.c_wchar)
        props_size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + name_buf_bytes
        props_buf = ctypes.create_string_buffer(props_size)
        props = ctypes.cast(props_buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES)).contents

        props.Wnode.BufferSize = props_size
        props.Wnode.Guid = system_trace_control_guid
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        props.Wnode.ClientContext = 1
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.EnableFlags = EVENT_TRACE_FLAG_PROCESS
        props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)

        name_addr = ctypes.addressof(props_buf) + props.LoggerNameOffset
        ctypes.memmove(name_addr, ctypes.create_unicode_buffer(session_name), name_buf_bytes)

        self._session_props_buf = props_buf

        rc = int(StartTraceW(ctypes.byref(self._session_handle), session_name, ctypes.byref(props)))
        self._session_started_by_us = rc == ERROR_SUCCESS
        if rc == ERROR_ALREADY_EXISTS:
            self._session_handle = ctypes.c_uint64(0)
            rc = ERROR_SUCCESS
        if rc != ERROR_SUCCESS:
            return False, rc

        def _get_uint_property(record_ptr: Any, name: str) -> int | None:
            name_buf = ctypes.create_unicode_buffer(name)
            desc = PROPERTY_DATA_DESCRIPTOR()
            desc.PropertyName = ctypes.cast(name_buf, ctypes.c_void_p).value or 0
            desc.ArrayIndex = 0xFFFFFFFF
            desc.Reserved = 0

            size = ctypes.c_uint32(0)
            rc_sz = int(TdhGetPropertySize(record_ptr, 0, None, 1, ctypes.byref(desc), ctypes.byref(size)))
            if rc_sz != ERROR_SUCCESS or int(size.value) <= 0:
                return None

            out = (ctypes.c_ubyte * int(size.value))()
            rc_val = int(TdhGetProperty(record_ptr, 0, None, 1, ctypes.byref(desc), size.value, ctypes.byref(out)))
            if rc_val != ERROR_SUCCESS:
                return None

            raw = bytes(out)
            if len(raw) >= 8:
                return int.from_bytes(raw[:8], byteorder="little", signed=False)
            if len(raw) >= 4:
                return int.from_bytes(raw[:4], byteorder="little", signed=False)
            return None

        def _record_callback(event_record_ptr):
            try:
                if not event_record_ptr:
                    return
                record = event_record_ptr.contents
                event_id = int(record.EventHeader.EventDescriptor.Id)
                opcode = int(record.EventHeader.EventDescriptor.Opcode)
                # Kernel process start event only.
                if not _is_process_start_event(event_id, opcode):
                    return

                pid = int(record.EventHeader.ProcessId)
                ppid = 0

                # Parse payload via TDH rather than fixed byte offsets.
                for pid_name in ("ProcessId", "ProcessID", "ProcessIdNew"):
                    parsed_pid = _get_uint_property(event_record_ptr, pid_name)
                    if parsed_pid and parsed_pid > 0:
                        pid = int(parsed_pid)
                        break

                for ppid_name in ("ParentId", "ParentProcessId", "ParentProcessID"):
                    parsed_ppid = _get_uint_property(event_record_ptr, ppid_name)
                    if parsed_ppid and parsed_ppid > 0:
                        ppid = int(parsed_ppid)
                        break

                if pid > 0:
                    self._on_process_start(pid, ppid, monotonic())
            except (OSError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
                self._callback_error_count += 1
                self._log_failure("event_callback", exc, self._callback_error_count)
                logger.debug("ETW event callback failed", exc_info=True)

        self._callback_fn = EVENT_RECORD_CALLBACK(_record_callback)

        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = session_name
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.EventRecordCallback = ctypes.cast(self._callback_fn, ctypes.c_void_p)

        trace_handle = int(OpenTraceW(ctypes.byref(logfile)))
        if trace_handle == int(INVALID_PROCESSTRACE_HANDLE):
            err = int(ctypes.get_last_error() or 0)
            self._stop_session()
            return False, (err if err else 1)

        self._trace_handle = ctypes.c_uint64(trace_handle)
        return True, 0

    def _close_trace(self) -> None:
        if not self._trace_handle.value:
            return
        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            CloseTrace = advapi32.CloseTrace
            CloseTrace.argtypes = [ctypes.c_uint64]
            CloseTrace.restype = ctypes.c_uint32
            CloseTrace(self._trace_handle.value)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
            self._close_error_count += 1
            self._log_failure("close_trace", exc, self._close_error_count)
            logger.debug("Failed to close ETW trace handle", exc_info=True)
        self._trace_handle = ctypes.c_uint64(0)

    def _stop_session(self) -> None:
        if not self._session_name:
            return
        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            ControlTraceW = advapi32.ControlTraceW
            ControlTraceW.argtypes = [
                ctypes.c_uint64,
                ctypes.c_wchar_p,
                ctypes.POINTER(EVENT_TRACE_PROPERTIES),
                ctypes.c_uint32,
            ]
            ControlTraceW.restype = ctypes.c_uint32

            if self._session_props_buf is None:
                return
            props = ctypes.cast(self._session_props_buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
            # Stop only if we created the session; otherwise detach quietly.
            if self._session_started_by_us:
                _ = ControlTraceW(self._session_handle.value, self._session_name, props, 1)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
            self._stop_error_count += 1
            self._log_failure("stop_session", exc, self._stop_error_count)
            logger.debug("Failed to stop ETW session", exc_info=True)
        self._session_handle = ctypes.c_uint64(0)
        self._session_name = ""
        self._session_started_by_us = False
        self._session_props_buf = None
