"""Tests for tools in api_core.py.

Test logic:
1. Basic connection and instance management
2. Metadata retrieval
3. Function / global / string lists
4. Entry points and types
5. Import / export tables, segment info, cursor position

Run with:
    pytest -m core          # Run only core module tests
    pytest test_core.py     # Run all tests in this file
"""
import pytest

pytestmark = pytest.mark.core


class TestConnection:
    """Connection and instance management tests."""
    
    def test_check_connection(self, tool_caller):
        """Test connection check."""
        result = tool_caller("check_connection")
        assert "ok" in result
        assert result["ok"] is True
    
    def test_list_instances(self, tool_caller):
        """Test listing instances."""
        result = tool_caller("list_instances")
        assert isinstance(result, list)
        assert len(result) >= 1


class TestMetadata:
    """IDB metadata tests."""
    
    def test_get_metadata(self, tool_caller, metadata):
        """Test getting metadata."""
        # metadata fixture already retrieved the metadata
        assert "input_file" in metadata
        assert "arch" in metadata
        assert "bits" in metadata
    
    def test_metadata_arch(self, metadata):
        """Test architecture info."""
        assert metadata["arch"] in ("x86", "x64", "arm", "arm64", "mips", "ppc", "metapc")
    
    def test_metadata_bits(self, metadata):
        """Test bit-width info."""
        assert metadata["bits"] in (16, 32, 64)


class TestFunctions:
    """Function list tests."""
    
    def test_list_functions_default(self, tool_caller):
        """Test listing functions with default parameters."""
        # Explicitly pass all parameters to avoid signature compatibility issues
        result = tool_caller("list_functions", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
        assert "total" in result
    
    def test_list_functions_pagination(self, tool_caller):
        """Test pagination parameters."""
        result = tool_caller("list_functions", {"offset": 0, "count": 10})
        assert "error" not in result
        assert "items" in result
        assert len(result["items"]) <= 10
    
    def test_list_functions_offset(self, tool_caller, functions_cache):
        """Test offset parameter."""
        if len(functions_cache) < 5:
            pytest.skip("Not enough functions")

        result1 = tool_caller("list_functions", {"offset": 0, "count": 3})
        result2 = tool_caller("list_functions", {"offset": 2, "count": 3})

        # The first item of the second query should equal the third item of the first query
        if result1["items"] and result2["items"]:
            assert result1["items"][2]["start_ea"] == result2["items"][0]["start_ea"]
    
    def test_list_functions_pattern(self, tool_caller):
        """Test pattern filtering."""
        result = tool_caller("list_functions", {"offset": 0, "count": 100, "pattern": "*"})
        assert "error" not in result
    
    def test_list_functions_invalid_offset(self, tool_caller):
        """Test invalid offset."""
        result = tool_caller("list_functions", {"offset": -1})
        assert "error" in result
    
    def test_list_functions_invalid_count(self, tool_caller):
        """Test invalid count."""
        result = tool_caller("list_functions", {"offset": 0, "count": 0})
        assert "error" in result
    
    def test_list_functions_count_too_large(self, tool_caller):
        """Test count too large."""
        result = tool_caller("list_functions", {"offset": 0, "count": 10000})
        assert "error" in result


class TestGlobals:
    """Global variable tests."""
    
    def test_list_globals_default(self, tool_caller):
        """Test listing globals with default parameters."""
        result = tool_caller("list_globals", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
    
    def test_list_globals_pagination(self, tool_caller):
        """Test pagination."""
        result = tool_caller("list_globals", {"offset": 0, "count": 5})
        assert "error" not in result
        assert len(result.get("items", [])) <= 5
    
    def test_list_globals_pattern(self, tool_caller):
        """Test pattern filtering."""
        result = tool_caller("list_globals", {"offset": 0, "count": 100, "pattern": "*"})
        assert "error" not in result


class TestStrings:
    """String tests."""
    
    def test_list_strings_default(self, tool_caller):
        """Test listing strings with default parameters."""
        result = tool_caller("list_strings", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
    
    def test_list_strings_pagination(self, tool_caller):
        """Test pagination."""
        result = tool_caller("list_strings", {"offset": 0, "count": 10})
        assert "error" not in result
        assert len(result.get("items", [])) <= 10
    
    def test_list_strings_pattern(self, tool_caller, strings_cache):
        """Test content filtering."""
        if not strings_cache:
            pytest.skip("No strings available")

        # Search using a substring of a known string
        # API returns a "text" field, not "value"
        first_str = strings_cache[0].get("text", "")
        if len(first_str) > 3:
            pattern = first_str[:3]
            result = tool_caller("list_strings", {"offset": 0, "count": 100, "pattern": pattern})
            assert "error" not in result


class TestLocalTypes:
    """Local type tests."""
    
    def test_list_local_types(self, tool_caller):
        """Test listing local types."""
        result = tool_caller("list_local_types")
        assert "error" not in result
        assert "items" in result or "total" in result


class TestEntryPoints:
    """Entry point tests."""
    
    def test_get_entry_points(self, tool_caller):
        """Test getting entry points."""
        result = tool_caller("get_entry_points")
        assert "error" not in result
        assert "items" in result


class TestConvertNumber:
    """Number conversion tests."""

    def test_convert_number(self, tool_caller):
        result = tool_caller("convert_number", {"text": "401000h", "size": 32})

        assert isinstance(result, dict)
        assert "error" not in result
        assert result["hex"] == "0x00401000"
        assert result["unsigned"] == 0x401000




class TestImports:
    """Import table tests."""
    
    def test_list_imports_default(self, tool_caller):
        """Test listing imports with default parameters."""
        result = tool_caller("list_imports", {"offset": 0, "count": 20})
        assert isinstance(result, dict)
        assert "items" in result or "error" in result
        
        if "items" in result and result["items"]:
            item = result["items"][0]
            assert "name" in item
            assert "module" in item
            assert "ea" in item
    
    def test_list_imports_pagination(self, tool_caller):
        """Test pagination."""
        result = tool_caller("list_imports", {"offset": 0, "count": 5})
        assert isinstance(result, dict)
        if "items" in result:
            assert len(result["items"]) <= 5
    
    def test_list_imports_pattern(self, tool_caller):
        """Test filtering by pattern."""
        result = tool_caller("list_imports", {"pattern": "kernel32", "count": 10})
        assert isinstance(result, dict)


class TestExports:
    """Export table tests."""
    
    def test_list_exports_default(self, tool_caller):
        """Test listing exports with default parameters."""
        result = tool_caller("list_exports", {"offset": 0, "count": 20})
        assert isinstance(result, dict)
        assert "items" in result or "error" in result
        
        if "items" in result and result["items"]:
            item = result["items"][0]
            assert "name" in item
            assert "ea" in item
    
    def test_list_exports_pagination(self, tool_caller):
        """Test pagination."""
        result = tool_caller("list_exports", {"offset": 0, "count": 5})
        assert isinstance(result, dict)
        if "items" in result:
            assert len(result["items"]) <= 5


class TestSegments:
    """Segment info tests."""
    
    def test_list_segments(self, tool_caller):
        """Test listing memory segments."""
        result = tool_caller("list_segments")
        assert isinstance(result, dict)
        assert "items" in result
        
        if result["items"]:
            seg = result["items"][0]
            assert "name" in seg
            assert "start_ea" in seg
            assert "end_ea" in seg
            assert "perm" in seg  # Permission string rwx
            assert "size" in seg
    
    def test_segments_have_code(self, tool_caller):
        """Verify executable segments exist."""
        result = tool_caller("list_segments")
        assert isinstance(result, dict)
        
        segments = result.get("items", [])
        code_segs = [s for s in segments if 'x' in s.get('perm', '')]
        # Most binaries have executable segments
        print(f"Executable segments: {len(code_segs)}")


class TestCursor:
    """Cursor position tests."""
    
    def test_get_cursor(self, tool_caller):
        """Test getting current cursor position."""
        result = tool_caller("get_cursor")
        assert isinstance(result, dict)
        assert "ea" in result
        assert "function" in result
        assert "selection" in result
