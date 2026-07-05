#!/usr/bin/env python3
"""Test script to validate the refactored architecture."""

import sys
import os

# Add src to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

def test_core_modules():
    """Test that all core modules can be imported successfully."""
    print("Testing core modules...")
    
    # Test basic plugin module
    try:
        from reconforge.core.plugin import BasePlugin
        print("  ✓ Basic plugin module imported")
    except Exception as e:
        print(f"  ✗ Basic plugin import error: {e}")
        return False
    
    # Test tool provider module
    try:
        from reconforge.core.tool_provider import ToolProvider
        print("  ✓ Tool provider module imported")
    except Exception as e:
        print(f"  ✗ Tool provider import error: {e}")
        return False
    
    # Test projectdiscovery provider module
    try:
        from reconforge.core.projectdiscovery_provider import ProjectDiscoveryTool
        print("  ✓ ProjectDiscoveryTool imported")
    except Exception as e:
        print(f"  ✗ ProjectDiscoveryTool import error: {e}")
        return False
    
    # Test tool registry module
    try:
        from reconforge.core.tool_registry import ToolRegistry
        print("  ✓ ToolRegistry imported")
    except Exception as e:
        print(f"  ✗ ToolRegistry import error: {e}")
        return False
    
    # Test enhanced plugin module
    try:
        from reconforge.core.enhanced_plugin import EnhancedBasePlugin
        print("  ✓ Enhanced plugin module imported")
    except Exception as e:
        print(f"  ✗ Enhanced plugin import error: {e}")
        return False
    
    # Test enhanced pipeline module
    try:
        from reconforge.core.enhanced_pipeline import EnhancedPipeline
        print("  ✓ Enhanced pipeline module imported")
    except Exception as e:
        print(f"  ✗ Enhanced pipeline import error: {e}")
        return False
    
    print("✓ All core modules imported successfully!")
    return True

def test_imports():
    """Test specific imports that were failing."""
    print("\nTesting specific imports...")
    
    # Test enhanced_plugin imports
    try:
        from reconforge.core.enhanced_plugin import ResultType
        print("  ✓ ResultType imported from enhanced_plugin")
    except Exception as e:
        print(f"  ✗ ResultType import error: {e}")
        return False
    
    # Test enhanced_pipeline imports
    try:
        from reconforge.core.enhanced_pipeline import EnhancedPipeline
        print("  ✓ EnhancedPipeline imported successfully")
    except Exception as e:
        print(f"  ✗ EnhancedPipeline import error: {e}")
        return False
    
    # Test tool_registry imports
    try:
        from reconforge.core.tool_registry import get_global_registry
        print("  ✓ get_global_registry imported")
    except Exception as e:
        print(f"  ✗ get_global_registry import error: {e}")
        return False
    
    print("✓ All specific imports working!")
    return True

def test_tool_registry():
    """Test ToolRegistry functionality."""
    print("\nTesting ToolRegistry...")
    
    try:
        from reconforge.core.tool_registry import ToolRegistry
        
        # Create a registry instance
        registry = ToolRegistry()
        print("  ✓ ToolRegistry instantiated")
        
        # Test registry methods
        tools = registry.get_all_tools()
        print(f"  ✓ Registry has {len(tools)} tools: {tools}")
        
        # Test tool availability check
        for tool_name in ["httpx", "naabu", "katana", "subfinder"]:
            try:
                available = registry.is_tool_available(tool_name)
                print(f"  ✓ Tool {tool_name} available: {available}")
            except ValueError:
                print(f"  - Tool {tool_name} not registered (expected)")
        
        print("  ✓ ToolRegistry functionality tested")
        return True
        
    except Exception as e:
        print(f"  ✗ ToolRegistry error: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing ReconForge Refactored Architecture")
    print("=" * 60)
    
    tests = [
        ("Core Modules Import", test_core_modules),
        ("Specific Imports", test_imports),
        ("Tool Registry", test_tool_registry),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        if test_func():
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Test Summary: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("✓ All tests passed! The refactored architecture is working.")
        return 0
    else:
        print("✗ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())