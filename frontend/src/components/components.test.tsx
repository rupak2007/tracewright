import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { EvidenceOut, FindingOut } from "../api/client";
import { SeverityBadge } from "./Badges";
import { TechniqueCards, WarningsList } from "./Cards";
import { EvidenceTable } from "./EvidenceTable";
import { FindingCard } from "./FindingCard";
import { SummaryPanel } from "./SummaryPanel";

// a DNS name an attacker could put on the wire, aimed at any UI that renders it as HTML
const HOSTILE = "<img src=x onerror=alert(1)>.tunnel.example.net";

const finding: FindingOut = {
  id: 7,
  local_id: "F-2",
  type: "SCAN",
  detector_id: "DET-SCAN",
  detector_version: "1.0.0",
  primary_entity: "10.0.0.5",
  secondary_entities: [HOSTILE],
  start_ts: "2026-11-02T10:00:00Z",
  end_ts: "2026-11-02T10:00:30Z",
  metrics: { scan_type: "vertical", distinct_dst_ports: 60, failed_share: 0.9 },
  thresholds: { vertical_ports: 50, high_failed_share: 0.6 },
  confidence: "high",
  severity_score: 2,
  benign_causes: ["vulnerability scanners", HOSTILE],
  evidence_total: 60,
  techniques: [{ technique_id: "T1046", phrase: "consistent with network service discovery" }],
  feedback: [],
};

describe("FindingCard", () => {
  it("shows each metric against its threshold with a text verdict, not colour alone", () => {
    render(<FindingCard finding={finding} playbooks={["K-PB-DET-SCAN"]} evidenceId="E-1" />);
    expect(screen.getByRole("heading", { name: /F-2 SCAN/ })).toBeInTheDocument();
    expect(screen.getByText("high confidence")).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /Distinct destination ports \(vertical\): 60 against threshold 50/ }),
    ).toBeInTheDocument();
    expect(screen.getAllByLabelText("threshold met").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/T1046 consistent with network service discovery/)).toBeInTheDocument();
    expect(screen.getByText(/consistent with, not attribution/)).toBeInTheDocument();
    expect(screen.getByText(/measured values: E-1/)).toBeInTheDocument();
  });

  it("renders hostile capture-derived strings as text, never as elements", () => {
    const { container } = render(<FindingCard finding={finding} playbooks={[]} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
  });
});

describe("EvidenceTable", () => {
  const items: EvidenceOut[] = [
    { local_id: "E-1", kind: "aggregate", finding_id: 7, zeek_uid: null, ts: null, fields: { events: 30 } },
    {
      local_id: "E-2",
      kind: "dns",
      finding_id: 7,
      zeek_uid: "C1",
      ts: "2026-11-02T10:00:01Z",
      fields: { query: HOSTILE, rcode: "NXDOMAIN", empty: null },
    },
  ];

  it("renders a DNS name containing markup as inert text (XSS fixture)", () => {
    const { container } = render(<EvidenceTable items={items} total={2} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("td.fields")?.textContent ?? "").toContain("events=30");
    expect(container.textContent).toContain(`query=${HOSTILE}`);
    expect(screen.queryByText(/empty=/)).toBeNull(); // null fields are dropped
  });

  it("gives every row its E-n id as an anchor and offers more only when some are missing", async () => {
    const onMore = vi.fn();
    render(<EvidenceTable items={items} total={5} onLoadMore={onMore} />);
    expect(document.getElementById("E-1")).not.toBeNull();
    expect(document.getElementById("E-2")).not.toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /3 left/ }));
    expect(onMore).toHaveBeenCalledOnce();
  });

  it("shows no 'more' button when everything is loaded", () => {
    render(<EvidenceTable items={items} total={2} onLoadMore={() => undefined} />);
    expect(screen.queryByRole("button")).toBeNull();
  });
});

describe("SummaryPanel", () => {
  it("turns citations into chips that move focus to the cited evidence row", async () => {
    render(
      <>
        <SummaryPanel summary={"Incident I-1 (high, score 4.0) groups 1 finding(s); an ordering aid.\n10.0.0.5 did X. [E-1, E-2]"} />
        <table>
          <tbody>
            <tr id="E-1" tabIndex={-1}>
              <td>one</td>
            </tr>
            <tr id="E-2" tabIndex={-1}>
              <td>two</td>
            </tr>
          </tbody>
        </table>
      </>,
    );
    expect(screen.getByText(/Incident I-1/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Go to evidence E-2" }));
    expect(document.getElementById("E-2")).toHaveFocus();
  });

  it("keeps markup in a sentence as text", () => {
    const { container } = render(<SummaryPanel summary={`hdr\n<b>${HOSTILE}</b> [E-1]`} />);
    expect(container.querySelector("b")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("badges and cards", () => {
  it("shows severity as words plus a shape", () => {
    render(<SeverityBadge label="critical" score={7.5} />);
    const badge = screen.getByText(/critical/);
    expect(badge.textContent).toContain("▲");
    expect(within(badge).getByText(/7.5/)).toBeInTheDocument();
  });

  it("never links a non-ATT&CK url and prints descriptions as text", () => {
    const card = {
      technique_id: "T1046",
      knowledge_id: "K-T1046",
      name: "Network Service Discovery",
      description: HOSTILE,
      tactics: ["discovery"],
      url: "javascript:alert(1)",
    };
    const { container } = render(
      <>
        <TechniqueCards cards={[card]} />
        <WarningsList warnings={[{ code: "NO_DNS", message: "No DNS observed" }]} />
      </>,
    );
    expect(container.querySelector("a")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(/Source: MITRE ATT&CK \(n\/a\)/)).toBeInTheDocument();
    expect(screen.getByText("NO_DNS")).toBeInTheDocument();
  });
});
