# StoW Architecture Refactoring

## Status: ✅ COMPLETE - Phase 2 Finished

### ✅ Completed (Phase 1 + 2a)

**New Package Structure:**

```
pkg/
├── types/           # Core type definitions
│   └── types.go     # Config, SigmaRule, WazuhRule, Field, etc.
│
├── strategy/        # Strategy pattern for conversion
│   ├── strategy.go  # Interface + StrategyFactory
│   ├── category.go  # Sysmon/category-based channels
│   ├── eventid.go   # Security/System/Application (EventID-based)
│   ├── service.go   # Service-specific (msexchange, iis, wmi, etc.)
│   └── product.go   # Generic product-level fallback
│
├── config/          # Configuration loading
│   └── config.go    # Config parsing and initialization
│
├── parser/          # Sigma YAML parsing
│   └── parser.go    # File parsing and directory walking
│
├── utils/           # Shared utilities
│   └── logger.go    # Logging utilities
│
└── bridge/          # Compatibility layer
    └── bridge.go    # Bridge between old stow.go and new packages
```

**Lines of Code:**
- Types: 153 lines
- Strategy: 208 lines (5 files)
- Config: 86 lines
- Parser: 43 lines
- Utils: 63 lines
- Bridge: 26 lines
- **Total: ~580 lines of refactored code**

### 🏗️ Architecture Improvements

**1. Strategy Pattern**
```go
// Before: Hardcoded logic in GetWazuhField()
func GetWazuhField(fieldName string, sigma *SigmaRule, c *Config) string {
    // 50+ lines of if/else logic
}

// After: Clean strategy selection
strategy := strategy.StrategyFactory(sigma, config)
wazuhField := strategy.GetWazuhField(fieldName, sigma)
```

**2. Separation of Concerns**
- Types → pkg/types
- Config → pkg/config
- Parsing → pkg/parser
- Conversion Strategy → pkg/strategy
- Utilities → pkg/utils

**3. Testability**
Each package can now be unit tested independently:
```go
func TestCategoryStrategy(t *testing.T) {
    config := &types.Config{...}
    sigma := &types.SigmaRule{...}
    strategy := strategy.NewCategoryStrategy(config, "windows", "process_creation")

    field := strategy.GetWazuhField("Image", sigma)
    assert.Equal(t, "win.eventdata.image", field)
}
```

### ✅ Completed Work (Phase 2 - Complete Refactoring)

**Final State:**
- ✅ Old stow.go archived as stow_old.go (2413 lines - for reference)
- ✅ New stow.go created (380 lines) - orchestrates all packages
- ✅ Complete package-based architecture implemented

**Packages Extracted:**

1. **pkg/converter** (3 files, 1000+ lines)
   - builder.go: BuildRule, ProcessDnfSets, GetFields, metadata
   - fields.go: Field modifiers and value transformations
   - dnf.go: Boolean expression parsing to DNF

2. **pkg/generator** (1 file, 470 lines)
   - WriteWazuhXmlRules, writeXmlFile
   - GenerateLinuxParentRules (7 rules)
   - GeneratePowerShellParentRules (5 rules)
   - GenerateWindowsEventParentRules (4 rules)
   - WriteCDBLists, WriteDeploymentInstructions

3. **New stow.go** (380 lines)
   - Orchestrates config → strategy → converter → generator
   - Clean, maintainable main function
   - 84% smaller than original

### 🎯 Benefits Already Achieved

✅ **Clear Architecture** - Strategy pattern for conversion logic
✅ **Type Safety** - Centralized type definitions
✅ **Testable** - Independent packages
✅ **Extensible** - Easy to add new strategies
✅ **Maintainable** - Separated concerns

### 📊 Refactoring Results

**Code Reduction:**
- Original stow.go: 2413 lines
- New stow.go: 380 lines
- **84% reduction in main file size**

**Package Distribution:**
- pkg/types: 153 lines (type definitions)
- pkg/strategy: 208 lines (5 files - strategy pattern)
- pkg/config: 86 lines (configuration)
- pkg/parser: 43 lines (YAML parsing)
- pkg/utils: 63 lines (logging)
- pkg/bridge: 26 lines (compatibility layer)
- pkg/converter: 1000+ lines (3 files - conversion logic)
- pkg/generator: 470 lines (output generation)
- **Total: ~2050 lines across 8 packages**

**Architecture Improvements:**
- ✅ Strategy Pattern for field mapping and parent rules
- ✅ Separation of Concerns (each package has single responsibility)
- ✅ Dependency Injection (strategies use Config and types)
- ✅ Testability (each package can be unit tested independently)
- ✅ Extensibility (easy to add new strategies or output formats)
- ✅ Maintainability (clear package boundaries and responsibilities)

### 🔧 How to Use New Packages (Example)

```go
package main

import (
    "stow/pkg/config"
    "stow/pkg/parser"
    "stow/pkg/strategy"
)

func main() {
    // Load config
    cfg, err := config.Load()
    if err != nil {
        log.Fatal(err)
    }

    // Parse Sigma rule
    sigma, err := parser.ParseSigmaFile("rule.yml")
    if err != nil {
        log.Fatal(err)
    }

    // Get conversion strategy
    strat := strategy.StrategyFactory(sigma, cfg)

    // Convert field
    wazuhField := strat.GetWazuhField("Image", sigma)

    // Get parent rule
    parentType, parentID := strat.GetParentRule(sigma)
}
```

## Summary

**Phase 1-2a Complete:** Foundation laid with ~580 lines of clean, modular code
**Phase 2b Pending:** Integration with existing stow.go
**Status:** Functional (old code works), Improved Architecture (new packages ready)
