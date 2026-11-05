import { render, screen, waitFor } from "@testing-library/react";

import RuntimeBlocksCard from "./RuntimeBlocksCard.jsx";

const mockGetRuntimeBlocks = jest.fn();

jest.mock("@/lib/api", () => ({
  dashboard: {
    getRuntimeBlocks: (...args) => mockGetRuntimeBlocks(...args),
  },
}));

const makeBlock = (overrides = {}) => ({
  id: "block-1",
  platform: "claude_code",
  gate: "install",
  reason: "unpinned_install_source",
  verdict: "block",
  created_at: "2025-01-02T03:04:05Z",
  ...overrides,
});

describe("RuntimeBlocksCard", () => {
  beforeEach(() => {
    mockGetRuntimeBlocks.mockReset();
  });

  it("shows a loading state until blocks resolve", () => {
    mockGetRuntimeBlocks.mockReturnValue(new Promise(() => {}));

    render(<RuntimeBlocksCard />);

    expect(screen.getByTestId("runtime-blocks-loading")).toBeInTheDocument();
  });

  it("lists platform, gate, reason, and time for each block", async () => {
    mockGetRuntimeBlocks.mockResolvedValue({
      data: {
        blocks: [makeBlock({ platform: "claude_code", gate: "install" })],
      },
    });

    render(<RuntimeBlocksCard />);

    const items = await screen.findAllByTestId("runtime-block-item");
    expect(items).toHaveLength(1);
    expect(items[0]).toHaveTextContent("claude_code");
    expect(items[0]).toHaveTextContent("Install gate");
    expect(items[0]).toHaveTextContent("Reason: unpinned_install_source");
    expect(items[0]).toHaveTextContent(
      new Date("2025-01-02T03:04:05Z").toLocaleString(),
    );
    expect(
      screen.queryByTestId("runtime-block-audit-only"),
    ).not.toBeInTheDocument();
  });

  it("labels return blocks on audit-only platforms as audit only", async () => {
    mockGetRuntimeBlocks.mockResolvedValue({
      data: {
        blocks: [
          makeBlock({
            id: "block-2",
            platform: "cursor",
            gate: "return",
            reason: "secret_detected",
          }),
        ],
      },
    });

    render(<RuntimeBlocksCard />);

    expect(
      await screen.findByTestId("runtime-block-audit-only"),
    ).toHaveTextContent("Audit only");
  });

  it("shows the empty state when no blocks are recorded", async () => {
    mockGetRuntimeBlocks.mockResolvedValue({ data: { blocks: [] } });

    render(<RuntimeBlocksCard />);

    expect(
      await screen.findByTestId("runtime-blocks-empty"),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("runtime-blocks-list")).not.toBeInTheDocument();
  });

  it("shows an error state when the request fails", async () => {
    mockGetRuntimeBlocks.mockRejectedValue(new Error("network down"));

    render(<RuntimeBlocksCard />);

    await waitFor(() =>
      expect(screen.getByTestId("runtime-blocks-error")).toBeInTheDocument(),
    );
  });
});
