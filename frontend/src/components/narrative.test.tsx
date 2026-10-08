import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { FindingOut, NarrativeOut } from "../api/client";
import { NarrativePanel, NarrativeView } from "./Narrative";

const HOSTILE = "<img src=x onerror=alert(1)>.evil.example";

const validated: NarrativeOut = {
  status: "validated",
  label: "Machine-generated narrative, validated against the evidence; the analyst decides.",
  provider: "ollama",
  model: "m1",
  prompt_hash: "a".repeat(64),
  reasons: [],
  created_at: null,
  entities: { H1: "10.0.0.5", D1: HOSTILE },
  output: {
    summary: "H1 shows a regular pattern.",
    observed: [{ statement: "H1 asked for D1 twice.", evidence_ids: ["E-1", "F-1"] }],
    inferences: [
      {
        statement: "Could be automation.",
        supporting_ids: ["E-1"],
        knowledge_ids: ["K-PB-DET-BEACON"],
        confidence: "low",
        alternative_explanations: ["a monitoring agent"],
      },
    ],
    recommendations: [{ action: "Check the jobs on H1.", rationale_ids: ["E-1"] }],
    open_questions: ["Is this expected?"],
  },
};

function withOutput(n: NarrativeOut) {
  if (!n.output) throw new Error("fixture has no output");
  return { ...n, output: n.output };
}

const finding = { id: 7, local_id: "F-1" } as FindingOut;

function wrap(node: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

function respond(...bodies: Array<NarrativeOut>) {
  const queue = [...bodies];
  const fetchMock = vi.fn<(url: string, init?: RequestInit) => Promise<Response>>(async () => {
    const body = queue.length > 1 ? queue.shift() : queue[0];
    return new Response(JSON.stringify(body), { status: 200 });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => vi.unstubAllGlobals());

describe("NarrativeView", () => {
  it("labels the text as machine-generated and validated, and shows the real values for pseudonyms", () => {
    render(<NarrativeView narrative={withOutput(validated)} onCite={() => {}} />);
    expect(screen.getByLabelText("validated against the evidence")).toBeInTheDocument();
    expect(screen.getByText(/the analyst decides/)).toBeInTheDocument();
    expect(screen.getByText("Inferences (hypotheses, not findings)")).toBeInTheDocument();
    expect(screen.getByText(/Could also be:/)).toHaveTextContent("a monitoring agent");
    expect(screen.getAllByText("10.0.0.5").length).toBeGreaterThan(0);
  });

  it("renders a hostile real value as inert text, never as markup", () => {
    const { container } = render(
      <NarrativeView narrative={withOutput(validated)} onCite={() => {}} />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
  });

  it("passes every cited id to the citation handler", async () => {
    const cited: string[] = [];
    render(<NarrativeView narrative={withOutput(validated)} onCite={(id) => cited.push(id)} />);
    await userEvent.click(screen.getByRole("button", { name: "Go to F-1" }));
    await userEvent.click(screen.getByRole("button", { name: "Go to K-PB-DET-BEACON" }));
    expect(cited).toEqual(["F-1", "K-PB-DET-BEACON"]);
  });
});

describe("NarrativePanel", () => {
  const base: NarrativeOut = { ...validated, status: "not_requested", output: null, entities: {}, provider: "none", model: "" };

  it("starts with the template as the default and a generate button", async () => {
    respond(base);
    wrap(<NarrativePanel incidentId={1} findings={[finding]} />);
    expect(await screen.findByText(/template summary above is the default/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate narrative" })).toBeEnabled();
  });

  it("shows a validated narrative after generation is requested", async () => {
    const fetchMock = respond(base, validated);
    wrap(<NarrativePanel incidentId={1} findings={[finding]} />);
    await userEvent.click(await screen.findByRole("button", { name: "Generate narrative" }));
    expect(await screen.findByLabelText("validated against the evidence")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Regenerate narrative" })).toBeInTheDocument();
    const post = fetchMock.mock.calls.find((c) => c[1]?.method === "POST");
    expect(post).toBeDefined();
  });

  it("never shows rejected text, only the fallback and the reasons", async () => {
    respond({ ...base, status: "rejected", reasons: ["check 5: verdict language 'is compromised' is not allowed"] });
    wrap(<NarrativePanel incidentId={1} findings={[finding]} />);
    expect(await screen.findByText(/did not pass validation and is not shown/)).toBeInTheDocument();
    expect(screen.getByText(/check 5/)).toBeInTheDocument();
    expect(screen.queryByLabelText("validated against the evidence")).toBeNull();
  });

  it("explains an unavailable provider", async () => {
    respond({ ...base, status: "unavailable", reasons: ["LLM_PROVIDER is none"] });
    wrap(<NarrativePanel incidentId={1} findings={[finding]} />);
    expect(await screen.findByText(/No narrative is available/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("LLM_PROVIDER is none")).toBeInTheDocument());
  });

  it("disables the button while a narrative is pending", async () => {
    respond({ ...base, status: "pending" });
    wrap(<NarrativePanel incidentId={1} findings={[finding]} />);
    expect(await screen.findByRole("status")).toHaveTextContent("Generating and validating");
    expect(screen.getByRole("button", { name: "Generate narrative" })).toBeDisabled();
  });
});
