# DigitalLogicSimulator

> **This project is incomplete and under active development.** It is published in progress, with its current defects documented below. It is not listed in the root README and is not ready to be evaluated as finished work.

# 1. Introduction

A headless, gate-level digital logic simulator with 4-state logic (`0`, `1`, `X`, `Z`), structural Verilog input, and VCD output.

# 2. Status

| Milestone | Description                                                | Status                                                   |
| --------- | ---------------------------------------------------------- | -------------------------------------------------------- |
| M0        | CI/CD (format, clang-tidy, cppcheck, ASan/UBSan, coverage) | Done                                                     |
| M1        | `Logic4` value model                                       | Implemented — **not externally verified** (see D2)       |
| M2        | Netlist IR (SoA) + builder                                 | Done                                                     |
| M3        | Event-driven kernel + delta cycles                         | Implemented — **known defect** (see D1)                  |
| M4        | VCD writer                                                 | Implemented — never diffed against a reference simulator |
| M5        | Structural Verilog parser                                  | In progress                                              |
| M6        | Differential testing (Icarus Verilog) + scale              | Not started                                              |
| M7        | Static timing analysis                                     | Not started                                              |

`src/benchmark/benchmark.cpp` is an empty placeholder. `src/common/main.cpp` is a stub; there is no CLI yet.

# 3. Known Defects

## 3-1. Unit-delay oscillation is not detected (`src/core/kernel.cpp`)

`Kernel::EvaluateGate` schedules every output change at `now + gate.delay`. With the default unit-delay model (`kDefaultDelay = 1`), no event is ever scheduled at the current simulation time, so the delta-cycle loop executes exactly once per time step and `max_delta_cycles` can never be exceeded.

Consequently, `RunStatus::kOscillation` is unreachable under the default delay model, and a unit-delay ring oscillator causes `Kernel::Run()` to loop forever.

## 3-2. `logic4_test.cpp` is tautological

The unit tests restate the same truth tables that `logic4.h` defines. A wrong table would be restated identically in the test and the test would pass. These tests demonstrate coverage, not correctness.

## 3-3. `KernelOscillation.DeltaCycleCapHalts` does not test oscillation

It drives a finite chain of zero-delay buffers with an artificially lowered cap. It verifies that the delta-cycle counter counts. It does not verify oscillation detection, and it did not catch 3-1.
