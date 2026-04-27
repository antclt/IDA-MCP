"""IDA version compatibility layer.

Handles API differences between IDA 8.x and IDA 9.x.
IDA 9.x removed the ida_struct module; struct operations now use ida_typeinf.
"""
from __future__ import annotations

from typing import Optional, Any

try:
    import idaapi  # type: ignore
except ImportError:
    idaapi = None

# detect IDA version
if idaapi:
    IDA_VERSION = idaapi.IDA_SDK_VERSION if hasattr(idaapi, 'IDA_SDK_VERSION') else 0
else:
    IDA_VERSION = 0
IDA9_OR_LATER = IDA_VERSION >= 900

# try importing ida_struct (IDA 8.x)
try:
    import ida_struct as _ida_struct  # type: ignore
    HAS_IDA_STRUCT = True
except ImportError:
    _ida_struct = None
    HAS_IDA_STRUCT = False

try:
    import ida_typeinf  # type: ignore
except ImportError:
    ida_typeinf = None

try:
    import idc  # type: ignore
except ImportError:
    idc = None


# ============================================================================
# Struct ID and retrieval
# ============================================================================

def get_struc_id(name: str) -> int:
    """Get struct ID."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_struc_id(name)  # type: ignore
    # IDA 9.x: use idc
    return idc.get_struc_id(name)


def get_struc(sid: int) -> Any:
    """Get struct object."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_struc(sid)  # type: ignore
    # IDA 9.x: return sid itself as identifier
    if sid == idaapi.BADADDR:
        return None
    return sid


def get_struc_size(s: Any) -> int:
    """Get struct size."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_struc_size(s)  # type: ignore
    # IDA 9.x: s is sid
    if s is None:
        return 0
    result = idc.get_struc_size(s)
    return result if isinstance(result, int) else 0


# ============================================================================
# Member operations
# ============================================================================

def get_member(s: Any, offset: int) -> Any:
    """Get member at the given offset."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member(s, offset)  # type: ignore
    # IDA 9.x: use idc
    if s is None:
        return None
    mid = idc.get_member_id(s, offset)
    if mid == idaapi.BADADDR or mid == -1:
        return None
    # return a simple member object
    return _MemberCompat(s, offset, mid)


def get_member_by_name(s: Any, name: str) -> Any:
    """Get member by name."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_by_name(s, name)  # type: ignore
    # IDA 9.x: iterate to find
    if s is None:
        return None
    size = get_struc_size(s)
    offset = 0
    while offset < size:
        mid = idc.get_member_id(s, offset)
        if mid != idaapi.BADADDR and mid != -1:
            mname = idc.get_member_name(s, offset)
            if mname == name:
                return _MemberCompat(s, offset, mid)
            msize = idc.get_member_size(s, offset)
            if msize > 0:
                offset += msize
            else:
                offset += 1
        else:
            offset += 1
    return None


def get_first_member(s: Any) -> Any:
    """Get first member."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_first_member(s)  # type: ignore
    # IDA 9.x
    if s is None:
        return None
    return get_member(s, 0)


def get_next_member(s: Any, offset: int) -> Any:
    """Get next member."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_next_member(s, offset)  # type: ignore
    # IDA 9.x
    if s is None:
        return None
    size = get_struc_size(s)
    # skip current member
    msize = idc.get_member_size(s, offset)
    next_off = offset + (msize if msize > 0 else 1)
    while next_off < size:
        mid = idc.get_member_id(s, next_off)
        if mid != idaapi.BADADDR and mid != -1:
            return _MemberCompat(s, next_off, mid)
        next_off += 1
    return None


def get_member_name(mid_or_member: Any) -> Optional[str]:
    """Get member name."""
    if HAS_IDA_STRUCT:
        if isinstance(mid_or_member, int):
            return _ida_struct.get_member_name(mid_or_member)  # type: ignore
        return _ida_struct.get_member_name(mid_or_member.id)  # type: ignore
    # IDA 9.x
    if isinstance(mid_or_member, _MemberCompat):
        return idc.get_member_name(mid_or_member.sid, mid_or_member.offset)
    return None


def get_member_id(m: Any) -> int:
    """Get member ID."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_id(m)  # type: ignore
    # IDA 9.x
    if isinstance(m, _MemberCompat):
        return m.mid
    return idaapi.BADADDR


def get_member_size(m: Any) -> int:
    """Get member size."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_size(m)  # type: ignore
    # IDA 9.x
    if isinstance(m, _MemberCompat):
        return idc.get_member_size(m.sid, m.offset)
    return 0


def get_member_offset(m: Any) -> int:
    """Get member offset."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_offset(m)  # type: ignore
    # IDA 9.x
    if isinstance(m, _MemberCompat):
        return m.offset
    return 0


def get_member_tinfo(tif: Any, m: Any) -> bool:
    """Get member type information."""
    if HAS_IDA_STRUCT:
        return _ida_struct.get_member_tinfo(tif, m)  # type: ignore
    # IDA 9.x: use ida_typeinf
    # NOTE: get_numbered_type(m.sid) uses sid (struct id) as a numbered type
    # ordinal; in IDA 9.x this may need to switch to get_named_type or
    # get_type_by_tid. If stack-frame type retrieval fails on IDA 9.x, check here.
    if isinstance(m, _MemberCompat):
        try:
            # in IDA 9.x, struct member types must be retrieved via ida_typeinf
            sptr = ida_typeinf.get_idati().get_numbered_type(m.sid)
            if sptr:
                udt = ida_typeinf.udt_type_data_t()
                if sptr.get_udt_details(udt):
                    for udm in udt:
                        if udm.offset // 8 == m.offset:
                            tif.copy_from(udm.type)
                            return True
            return False
        except Exception:
            return False
    return False


# ============================================================================
# Member add/remove
# ============================================================================

def add_struc_member(
    s: Any,
    name: str,
    offset: int,
    flag: int,
    typeid: Any,
    size: int
) -> int:
    """Add struct member."""
    if HAS_IDA_STRUCT:
        return _ida_struct.add_struc_member(s, name, offset, flag, typeid, size)  # type: ignore
    # IDA 9.x: use idc
    if s is None:
        return -1
    result = idc.add_struc_member(s, name, offset, flag, typeid, size)
    return result if isinstance(result, int) else -1


def del_struc_member(s: Any, offset: int) -> bool:
    """Delete struct member."""
    if HAS_IDA_STRUCT:
        return _ida_struct.del_struc_member(s, offset)  # type: ignore
    # IDA 9.x: use idc
    if s is None:
        return False
    return bool(idc.del_struc_member(s, offset))


# ============================================================================
# Compatibility class
# ============================================================================

class _MemberCompat:
    """IDA 9.x member compatibility object."""
    
    def __init__(self, sid: int, offset: int, mid: int):
        self.sid = sid
        self.offset = offset
        self.mid = mid
        self.id = mid
        self.soff = offset
    
    def __bool__(self) -> bool:
        return self.mid != idaapi.BADADDR and self.mid != -1

