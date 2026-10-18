import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { BgpSessionStatus } from "@/components/dashboard/bgp-session-status"
import AdminPage from "@/app/(dashboard)/admin/page"
import type { HealthResponse } from "@/lib/api"

const mock = vi.hoisted(() => ({ health: undefined as HealthResponse | undefined, error: undefined as Error | undefined }))
vi.mock("@/hooks/use-api", () => ({
  useHealthDetail: () => ({ data: mock.health, error: mock.error, isLoading: !mock.health && !mock.error }),
  usePops: () => ({ data: [] }),
  useStats: () => ({}),
  useSafelist: () => ({ data: [] }),
  useOperators: () => ({ data: [] }),
}))
vi.mock("@/hooks/use-reduced-motion", () => ({ useReducedMotion: () => true }))
vi.mock("@/hooks/use-permissions", () => ({ usePermissions: () => ({}) }))
vi.mock("@/hooks/use-auth", () => ({ useAuth: () => ({ operator: null }) }))
vi.mock("@/components/dashboard/dashboard-layout", () => ({ DashboardLayout: ({ children }: { children: ReactNode }) => <>{children}</> }))

afterEach(cleanup)
beforeEach(() => { mock.health = undefined; mock.error = undefined })

function health(status: string, peers: Record<string, string> = {}): HealthResponse {
  return {
    status: "healthy", version: "test", pop: "test", uptime_seconds: 10,
    bgp_sessions: peers, active_mitigations: 0, database: "connected",
    gobgp: { status }, auth_mode: "none",
    bgp_session_up: status === "connected" && Object.keys(peers).length > 0 && Object.values(peers).every(state => state === "established"),
  }
}

describe("speaker observation UI", () => {
  it.each([
    ["unsupported", {}, "UNSUPPORTED", "BGP peer observation is unsupported by this speaker"],
    ["error", {}, "ERROR", "BGP peer observation failed"],
    ["connected", {}, "NO PEERS", "No BGP peers configured"],
    ["connected", { router: "established" }, "UP", "router"],
    ["connected", { router: "idle" }, "DOWN", "router"],
  ])("renders %s with %j peers distinctly in both views", (status, peers, badge, detail) => {
    // Older servers omit additive speaker metadata.
    mock.health = health(status as string, peers as Record<string, string>)
    render(<BgpSessionStatus />)
    expect(screen.getByText(badge as string)).toBeInTheDocument()
    render(<AdminPage />)
    expect(screen.getByText(detail as string)).toBeInTheDocument()
    expect(screen.queryByText(/FlowSpec announcements are active/)).not.toBeInTheDocument()
  })

  it.each([false, true, undefined])("annotates rule-reader availability only when explicitly false (%s)", (reader) => {
    mock.health = health("connected", { router: "established" })
    if (reader !== undefined) {
      mock.health.speaker = { backend: "test", capabilities: { rule_reader: reader, peer_observer: true } }
    }
    render(<AdminPage />)
    const annotation = screen.queryByText("Rule observation is unsupported by this speaker")
    if (reader === false) expect(annotation).toBeInTheDocument()
    else expect(annotation).not.toBeInTheDocument()
    expect(screen.getByText("router")).toBeInTheDocument()
    expect(screen.getByText("established")).toBeInTheDocument()
  })

  it("labels version and uptime as controller data, with backend and session counts separate", () => {
    mock.health = health("connected", { edge1: "established", edge2: "idle" })
    mock.health.version = "0.22.0"
    mock.health.uptime_seconds = 3660
    mock.health.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true } }
    render(<BgpSessionStatus />)
    const strip = screen.getByLabelText("Speaker and controller health")
    expect(screen.getByText("rustbgpd")).toBeInTheDocument()
    expect(screen.getByText("DOWN")).toBeInTheDocument()
    expect(strip).toHaveTextContent("1/2 established")
    expect(strip).toHaveTextContent("Controller v0.22.0 · up 1h 1m")
    expect(strip).not.toHaveTextContent(/installed|speaker version|speaker uptime/i)
  })

  it("keeps an initial health fetch separate from successful empty peers", () => {
    render(<BgpSessionStatus />)
    expect(screen.getByText("LOADING")).toBeInTheDocument()
    expect(screen.queryByText("NO PEERS")).not.toBeInTheDocument()
  })

  it("shows a fetch error instead of stale successful peer state", () => {
    mock.health = health("connected", { router: "established" })
    mock.error = new Error("offline")
    render(<BgpSessionStatus />)
    expect(screen.getByText("ERROR")).toBeInTheDocument()
    expect(screen.queryByText("UP")).not.toBeInTheDocument()
  })
})
