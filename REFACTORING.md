# StoW Architecture Refactoring

## Status: Phase 2 In Progress

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

### ⏳ Remaining Work (Phase 2b)

**Current State:**
- stow.go still exists (2413 lines) - fully functional ✅
- New packages exist but not yet integrated
- Both codebases coexist

**Integration Plan:**

1. **Gradual Migration** (recommended)
   - Replace `GetWazuhField()` in stow.go with `bridge.ConvertFieldName()`
   - Replace `GetIfGrpSid()` with `bridge.GetParentRuleID()`
   - Test after each change

2. **Extract Converter Package** (~800 lines)
   - BuildRule, ProcessDnfSets, GetFields
   - DNF logic (tokenize, parse, convertToDNF)
   - Field processing

3. **Extract Generator Package** (~400 lines)
   - WriteWazuhXmlRules, writeXmlFile
   - generateParentRules (Linux, PowerShell, Windows)
   - CDB list generation

4. **New main.go**
   - Orchestrate using new packages
   - Deprecate old stow.go

### 🎯 Benefits Already Achieved

✅ **Clear Architecture** - Strategy pattern for conversion logic
✅ **Type Safety** - Centralized type definitions
✅ **Testable** - Independent packages
✅ **Extensible** - Easy to add new strategies
✅ **Maintainable** - Separated concerns

### 📝 Next Steps

**Option A: Complete Integration Now** (~2-3 hours)
- Extract converter and generator packages
- Update stow.go to use all new packages
- Full testing

**Option B: Gradual Integration** (recommended)
- Use bridge package in stow.go
- Replace functions one by one
- Test incrementally
- Lower risk

**Option C: Keep as Foundation**
- New packages provide clean API
- Old stow.go still works
- Future development uses new architecture

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
