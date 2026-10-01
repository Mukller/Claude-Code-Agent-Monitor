/**
 * @file Tests for the privacy rule pattern validator. Rules are evaluated
 * against every hook payload string inside the processEvent SQLite
 * transaction, so a pattern with catastrophic backtracking would hold a write
 * transaction and stall ingestion. `new RegExp()` alone does not catch this:
 * `(a+)+$` compiles and takes ~4s on a 26-character non-matching input.
 * @author Son Nguyen <hoangson091104@gmail.com>
 */

const { describe, it, before } = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const path = require("node:path");

process.env.DASHBOARD_DB_PATH = path.join(
  os.tmpdir(),
  `privacy-pattern-safety-${Date.now()}-${process.pid}.db`
);

const { validateRulePattern } = require("../lib/privacy");

describe("validateRulePattern — accepts useful detectors", () => {
  const ACCEPT = [
    ["sk-ant-[A-Za-z0-9_-]{20,}", "realistic secret detector"],
    ["^Bearer\\s+", "anchored literal"],
    ["AKIA[0-9A-Z]{16}", "AWS key shape"],
    ["/home/[a-z]+/\\.ssh", "home path detector"],
    ["[a-z]+@[a-z]+\\.com", "email"],
    ["a{2,10}b", "bounded repetition"],
    ["(foo|bar)baz", "plain alternation"],
    ["(a+)?b", "optional group is not an unbounded quantified group"],
    ["x{1,3}", "bounded braces"],
    ["secret", "plain literal"],
  ];

  for (const [pattern, why] of ACCEPT) {
    it(`accepts ${JSON.stringify(pattern)} (${why})`, () => {
      const r = validateRulePattern(pattern);
      assert.ok(r.ok, `expected accepted, got: ${r.error}`);
    });
  }
});

describe("validateRulePattern — rejects unsafe patterns", () => {
  it("rejects (a+)+$ , the classic catastrophic backtracking shape", () => {
    const r = validateRulePattern("(a+)+$");
    assert.equal(r.ok, false);
    assert.match(r.error, /nested unbounded quantifiers/);
  });

  it("rejects (a*)*", () => {
    assert.equal(validateRulePattern("(a*)*").ok, false);
  });

  it("rejects (\\w+)*z", () => {
    assert.equal(validateRulePattern("(\\w+)*z").ok, false);
  });

  it("rejects (a|a)+", () => {
    assert.equal(validateRulePattern("(a|a)+").ok, false);
  });

  it("rejects a pattern over the length cap", () => {
    assert.equal(validateRulePattern("a".repeat(501)).ok, false);
  });

  it("still rejects an invalid regex", () => {
    const r = validateRulePattern("([a-z");
    assert.equal(r.ok, false);
    assert.match(r.error, /not a valid regex/);
  });

  it("allows an empty pattern, which the route treats as absent", () => {
    assert.equal(validateRulePattern("").ok, true);
  });
});

describe("known limit of the guard", () => {
  // Documents what this heuristic does NOT catch. Alternation where branches
  // differ but overlap, e.g. (a|aa)+$, backtracks exponentially without any
  // nested unbounded quantifier and without duplicate branches, so the guard
  // lets it through. Catching it needs a real automaton comparison, i.e. a
  // linear-time engine (RE2). Stated explicitly so nobody reads the passing
  // tests as "arbitrary user regexes are now safe".
  it("does not detect (a|aa)+ — that needs a linear-time engine", () => {
    assert.equal(validateRulePattern("(a|aa)+$").ok, true);
  });
});

describe("the rejected pattern really is slow", () => {
  it("(a+)+$ exceeds a sane budget on a 26-character input", () => {
    const re = new RegExp("(a+)+$");
    const input = "a".repeat(25) + "b";
    const t0 = process.hrtime.bigint();
    re.test(input);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    // Documents why the validator exists. Generous bound: the point is that
    // it is orders of magnitude slower than any real detector.
    assert.ok(ms > 50, `expected the pattern to be slow, took ${ms}ms`);
  });
});
