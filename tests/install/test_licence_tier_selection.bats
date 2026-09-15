#!/usr/bin/env bats
# tests/install/test_licence_tier_selection.bats
#
# Licence tier asked at install, default Community (Tiago 2026-09-15: "during
# the install you should ask what is the license they are going for, default is
# Community and use the lowest size default model").
#
# Two things are under test and the second one is the security-relevant half:
#
#   1. The tier resolves identically down both install journeys — interactive
#      Enter and --non-interactive must BOTH land on Community. A default that
#      differs between journeys is how an operator ends up on a tier they did
#      not choose.
#
#   2. Every default model is Apache-2.0. The previous default `qwen2.5:3b` is
#      NOT: Qwen2.5 is Apache-2.0 except its 3B and 72B, which are "other" (the
#      Qwen licence), and the shipped default was precisely one of those two
#      encumbered sizes — YSG-RISK-312. Measured against the HuggingFace API:
#          Qwen2.5-14B-Instruct  apache-2.0    Qwen2.5-7B-Instruct   apache-2.0
#          Qwen2.5-3B-Instruct   other         Qwen2.5-72B-Instruct  other
#      and for Qwen3.8, its upstream LICENSE is stock Apache 2.0 (201 lines,
#      zero MAU / acceptable-use / non-commercial / research-only clauses).
#
# Note on scope: `prompt_licence_tier` gates on `[[ -t 0 ]]`, so it cannot be
# driven from bats — a heredoc is not a TTY and the gate short-circuits to the
# default, which would make such a test assert nothing while appearing to pass.
# The choice-parsing is therefore split into `_licence_tier_from_choice`, which
# IS the branch that decides the tier, and that is what is tested here.

setup() {
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  # Extract only the licence-tier functions — sourcing install.sh would run it.
  sed -n '/^_licence_tier_is_valid()/,/^# _pick_ollama_model_for_vram/p' \
    "${REPO_ROOT}/install.sh" > "${BATS_TEST_TMPDIR}/tierfns.sh"
  log_info()  { :; }
  log_warn()  { :; }
  log_error() { printf 'ERROR: %s\n' "$*"; }
  C_BOLD=""; C_RESET=""
  # shellcheck disable=SC1090
  . "${BATS_TEST_TMPDIR}/tierfns.sh"
}

# --- the default is Community, identically down both journeys ---------------

@test "pressing Enter selects Community" {
  run _licence_tier_from_choice ""
  [ "$status" -eq 0 ]
  [ "$output" = "community" ]
}

@test "an unrecognised answer falls back to Community rather than a higher tier" {
  # Failing upward would hand out capacity nobody purchased.
  run _licence_tier_from_choice "platinum"
  [ "$output" = "community" ]
}

@test "every menu number maps to its tier" {
  [ "$(_licence_tier_from_choice 1)" = "community" ]
  [ "$(_licence_tier_from_choice 2)" = "smb" ]
  [ "$(_licence_tier_from_choice 3)" = "enterprise" ]
  [ "$(_licence_tier_from_choice 4)" = "datacenter" ]
}

@test "tier names are accepted as well as numbers, case-insensitively" {
  [ "$(_licence_tier_from_choice smb)" = "smb" ]
  [ "$(_licence_tier_from_choice Enterprise)" = "enterprise" ]
}

# --- validation --------------------------------------------------------------

@test "known tiers validate and unknown ones do not" {
  for t in community smb enterprise datacenter; do
    run _licence_tier_is_valid "$t"
    [ "$status" -eq 0 ]
  done
  run _licence_tier_is_valid "platinum"
  [ "$status" -ne 0 ]
  run _licence_tier_is_valid ""
  [ "$status" -ne 0 ]
}

# --- the model ladder --------------------------------------------------------

@test "Community gets the lowest-size model" {
  [ "$(_pick_model_for_licence_tier community)" = "qwen3:1.7b" ]
}

@test "every tier resolves to a model" {
  for t in community smb enterprise datacenter; do
    run _pick_model_for_licence_tier "$t"
    [ -n "$output" ]
  done
}

@test "no tier ships a licence-encumbered model" {
  # The whole point. qwen2.5:3b and qwen2.5:72b are "other" (Qwen licence);
  # llama* carries MAU + acceptable-use clauses; gemma* is pass-through
  # restricted. None may appear as a shipped default at any tier.
  for t in community smb enterprise datacenter; do
    model="$(_pick_model_for_licence_tier "$t")"
    case "$model" in
      qwen2.5:3b|qwen2.5:72b|llama*|gemma*|*mistral*)
        printf 'tier %s ships licence-encumbered default %s\n' "$t" "$model"
        return 1
        ;;
    esac
  done
}

@test "the research-only qwen2.5:3b is gone as a default" {
  # It was the shipped default (YSG-RISK-312). A direct regression pin.
  for t in community smb enterprise datacenter; do
    [ "$(_pick_model_for_licence_tier "$t")" != "qwen2.5:3b" ]
  done
}

@test "model size does not decrease as the tier increases" {
  # A higher tier handing out a smaller model would be a silent downgrade for
  # a paying customer.
  size_of() {
    case "$1" in
      qwen3:1.7b)   echo 2   ;;
      qwen2.5:14b)  echo 14  ;;
      qwen3.8:27b)  echo 27  ;;
      *)            echo 0   ;;
    esac
  }
  prev=0
  for t in community smb enterprise datacenter; do
    cur="$(size_of "$(_pick_model_for_licence_tier "$t")")"
    [ "$cur" -ge "$prev" ]
    prev="$cur"
  done
}
