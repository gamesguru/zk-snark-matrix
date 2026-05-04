import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic

namespace ctopology.RoutingGate

/-!
# Routing Gate Correctness (Lemma 4.2)

We formalize the core Beneš switch constraint from the paper §4.
All arithmetic is over GF(2) = ℤ/2ℤ, where:
  - Addition = XOR
  - Multiplication = AND
  - Subtraction = Addition (since -1 = 1 in characteristic 2)

## Main Results

- `routing_gate_straight`: When s = 0, the constraint forces y = a.
- `routing_gate_cross`: When s = 1, the constraint forces y = b.
- `switch_validity`: s * (s + 1) = 0 iff s ∈ {0, 1} (trivially true in ZMod 2).
-/

open ZMod

/--
  The routing constraint from the paper (Equation 2):
    C_route(s, a, b, y) := y + a + s * (a + b)

  This is the GF(2) algebraic multiplexer. In characteristic 2,
  the standard form (1-s)*a + s*b - y reduces to y + a + s*(a + b)
  because subtraction = addition and -1 = 1.
-/
def C_route (s a b y : ZMod 2) : ZMod 2 :=
  y + a + s * (a + b)

/--
  **Lemma 4.2a (Straight-through):**
  When s = 0, the constraint C_route = 0 forces y = a.
-/
theorem routing_gate_straight (a b y : ZMod 2)
    (h : C_route 0 a b y = 0) : y = a := by
  unfold C_route at h
  simp at h
  linarith

/--
  **Lemma 4.2b (Cross):**
  When s = 1, the constraint C_route = 0 forces y = b.
-/
theorem routing_gate_cross (a b y : ZMod 2)
    (h : C_route 1 a b y = 0) : y = b := by
  unfold C_route at h
  -- In ZMod 2, we can decide by exhaustive case analysis
  fin_cases a <;> fin_cases b <;> fin_cases y <;> simp_all

/--
  **Completeness (forward direction):**
  Setting y = a when s = 0 always satisfies the constraint.
-/
theorem routing_gate_complete_straight (a b : ZMod 2) :
    C_route 0 a b a = 0 := by
  unfold C_route
  ring

/--
  **Completeness (forward direction):**
  Setting y = b when s = 1 always satisfies the constraint.
-/
theorem routing_gate_complete_cross (a b : ZMod 2) :
    C_route 1 a b b = 0 := by
  unfold C_route
  fin_cases a <;> fin_cases b <;> simp_all

/--
  **Switch Validity Constraint:**
  s * (s + 1) = 0 in ZMod 2 for all s.

  This is the Boolean enforcement gate. In a general field, this
  constrains s to {0, 1}. In ZMod 2, it is trivially true since
  every element is already in {0, 1}.
-/
theorem switch_validity (s : ZMod 2) : s * (s + 1) = 0 := by
  fin_cases s <;> decide

/--
  **Full Routing Gate Correctness (Lemma 4.2):**
  The constraint C_route(s, a, b, y) = 0 is satisfied if and only if
  y equals the multiplexer output: y = a when s = 0, y = b when s = 1.
-/
theorem routing_gate_iff (s a b y : ZMod 2) :
    C_route s a b y = 0 ↔
      (s = 0 ∧ y = a) ∨ (s = 1 ∧ y = b) := by
  fin_cases s <;> fin_cases a <;> fin_cases b <;> fin_cases y <;> simp_all [C_route]

end ctopology.RoutingGate
