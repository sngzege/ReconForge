import sys
import os

# Add src to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

print("Testing enhanced plugin module imports...")

# Test importing the ProjectDiscoveryTool first
try:
    from reconforge.core.projectdiscovery_provider import ProjectDiscoveryTool
    print("✓ ProjectDiscoveryTool imported")
except Exception as e:
    print(f"✗ ProjectDiscoveryTool import error: {type(e).__name__}: {str(e)}")
    sys.exit(1)

# Test importing enhanced_plugin module
import reconforge.core.enhanced_plugin as ep
print("✓ Enhanced plugin module imported")

# Check if ResultType is accessible
print("✓ ResultType accessible:", hasattr(ep, 'ResultType'))

# Check if EnhancedBasePlugin is accessible
print("✓ EnhancedBasePlugin accessible:", hasattr(ep, 'EnhancedBasePlugin'))

# Test importing enhanced_pipeline module
try:
    import reconforge.core.enhanced_pipeline as ep2
    print("✓ Enhanced pipeline module imported")
except Exception as e:
    print(f"✗ Enhanced pipeline import error: {type(e).__name__}: {str(e)}")
    sys.exit(1)

print("\nAll imports successful!")