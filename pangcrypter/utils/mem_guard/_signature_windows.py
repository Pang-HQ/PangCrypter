from __future__ import annotations

from typing import Any

from ._deps import SignatureWindowsDeps


_WIN_VERIFY_TRUST_FN: Any = None


def _get_win_verify_trust(ctypes_module) -> Any:
    global _WIN_VERIFY_TRUST_FN
    if _WIN_VERIFY_TRUST_FN is not None:
        return _WIN_VERIFY_TRUST_FN
    wintrust = ctypes_module.WinDLL("wintrust", use_last_error=True)
    _WIN_VERIFY_TRUST_FN = wintrust.WinVerifyTrust
    return _WIN_VERIFY_TRUST_FN


def signature_status_windows(
    path: str,
    *,
    cache_only: bool,
    deps: SignatureWindowsDeps,
):
    ctypes_module = deps.ctypes_module
    wintypes_module = deps.wintypes_module
    os_module = deps.os_module
    is_mem_guard_supported_fn = deps.is_mem_guard_supported_fn
    is_windows_system_path_fn = deps.is_windows_system_path_fn
    SigResult = deps.SigResult
    SigTrust = deps.SigTrust

    structure_base = getattr(ctypes_module, "Structure")

    class GUID(structure_base):  # type: ignore[misc, valid-type]
        _fields_ = [
            ("Data1", ctypes_module.c_uint32),
            ("Data2", ctypes_module.c_uint16),
            ("Data3", ctypes_module.c_uint16),
            ("Data4", ctypes_module.c_ubyte * 8),
        ]

    if not is_mem_guard_supported_fn() or not path or not os_module.path.exists(path):
        return SigResult(SigTrust.UNKNOWN, 0)

    class WINTRUST_FILE_INFO(structure_base):  # type: ignore[misc, valid-type]
        _fields_ = [
            ("cbStruct", ctypes_module.c_uint32),
            ("pcwszFilePath", ctypes_module.c_wchar_p),
            ("hFile", ctypes_module.c_void_p),
            ("pgKnownSubject", ctypes_module.c_void_p),
        ]

    class WINTRUST_DATA(structure_base):  # type: ignore[misc, valid-type]
        _fields_ = [
            ("cbStruct", ctypes_module.c_uint32),
            ("pPolicyCallbackData", ctypes_module.c_void_p),
            ("pSIPClientData", ctypes_module.c_void_p),
            ("dwUIChoice", ctypes_module.c_uint32),
            ("fdwRevocationChecks", ctypes_module.c_uint32),
            ("dwUnionChoice", ctypes_module.c_uint32),
            ("pFile", ctypes_module.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes_module.c_uint32),
            ("hWVTStateData", ctypes_module.c_void_p),
            ("pwszURLReference", ctypes_module.c_wchar_p),
            ("dwProvFlags", ctypes_module.c_uint32),
            ("dwUIContext", ctypes_module.c_uint32),
            ("pSignatureSettings", ctypes_module.c_void_p),
        ]

    action_guid = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes_module.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    file_info = WINTRUST_FILE_INFO(
        cbStruct=ctypes_module.sizeof(WINTRUST_FILE_INFO),
        pcwszFilePath=path,
        hFile=None,
        pgKnownSubject=None,
    )
    data = WINTRUST_DATA(
        cbStruct=ctypes_module.sizeof(WINTRUST_DATA),
        pPolicyCallbackData=None,
        pSIPClientData=None,
        dwUIChoice=deps.WTD_UI_NONE,
        fdwRevocationChecks=deps.WTD_REVOKE_NONE,
        dwUnionChoice=deps.WTD_CHOICE_FILE,
        pFile=ctypes_module.pointer(file_info),
        dwStateAction=deps.WTD_STATEACTION_IGNORE,
        hWVTStateData=None,
        pwszURLReference=None,
        dwProvFlags=deps.WTD_CACHE_ONLY_URL_RETRIEVAL if cache_only else 0,
        dwUIContext=0,
        pSignatureSettings=None,
    )

    win_verify_trust = _get_win_verify_trust(ctypes_module)
    win_verify_trust.argtypes = [wintypes_module.HWND, ctypes_module.POINTER(GUID), ctypes_module.POINTER(WINTRUST_DATA)]
    win_verify_trust.restype = ctypes_module.c_long

    result = win_verify_trust(None, ctypes_module.byref(action_guid), ctypes_module.byref(data))
    status = ctypes_module.c_uint32(result).value
    if status == 0:
        return SigResult(SigTrust.SIGNED_TRUSTED, 0)
    if status == deps.TRUST_E_NOSIGNATURE:
        if is_windows_system_path_fn(path):
            return SigResult(SigTrust.UNKNOWN, status)
        return SigResult(SigTrust.UNSIGNED, status)
    if status in (deps.TRUST_E_SUBJECT_FORM_UNKNOWN, deps.TRUST_E_PROVIDER_UNKNOWN):
        return SigResult(SigTrust.UNKNOWN, status)
    return SigResult(SigTrust.SIGNED_UNTRUSTED, status)


def signature_status_with_fallback(
    path: str,
    *,
    signature_status_windows_fn,
    is_windows_system_path_fn,
    SigTrust,
):
    sig = signature_status_windows_fn(path, cache_only=True)
    if sig.trust == SigTrust.SIGNED_TRUSTED:
        return sig
    if is_windows_system_path_fn(path) and sig.trust in {SigTrust.UNKNOWN, SigTrust.SIGNED_UNTRUSTED}:
        return signature_status_windows_fn(path, cache_only=False)
    return sig
