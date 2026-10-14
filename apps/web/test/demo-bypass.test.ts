import { describe, expect, it } from "vitest";
import { isDemoBypassHost } from "../src/flows.js";

describe("demo bypass hostname allowlist", () => {
  it("engages on loopback names", () => {
    expect(isDemoBypassHost("localhost")).toBe(true);
    expect(isDemoBypassHost("127.0.0.1")).toBe(true);
    expect(isDemoBypassHost("::1")).toBe(true);
    expect(isDemoBypassHost("[::1]")).toBe(true);
    expect(isDemoBypassHost("LOCALHOST")).toBe(true);
  });

  it("refuses everything else", () => {
    expect(isDemoBypassHost("example.com")).toBe(false);
    expect(isDemoBypassHost("app.example.com")).toBe(false);
    expect(isDemoBypassHost("192.168.1.10")).toBe(false);
    expect(isDemoBypassHost("")).toBe(false);
    expect(isDemoBypassHost("localhost.example.com")).toBe(false);
    expect(isDemoBypassHost("evillocalhost")).toBe(false);
  });
});
