import Lake
open Lake DSL

package «ctopology» where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩, -- pretty-print `fun a ↦ b`
    ⟨`autoImplicit, false⟩
  ]

require «doc-gen4» from git
  "https://github.com/leanprover/doc-gen4" @ "main"

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git"

@[default_target]
lean_lib «ctopology» where
  srcDir := "lean_src"
  -- Library configuration
