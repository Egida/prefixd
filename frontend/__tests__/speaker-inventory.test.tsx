import { act, fireEvent, screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import InventoryPage from "@/app/(dashboard)/inventory/page"
import { LocalFlowSpecInventory } from "@/components/dashboard/local-flowspec-inventory"
import type { SpeakerRoutesResponse } from "@/lib/api"
import { deferred, failure, json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const routes: SpeakerRoutesResponse["routes"] = [
  {
    nlri: {
      dst_prefix: "203.0.113.10/32", src_prefix: "198.51.100.0/24", protocol: 17,
      dst_ports: [53, 443], src_ports: [123, 389], packet_length: { min: 468, max: 1500 },
    },
    actions: [{ action_type: "police", rate_bps: 125_000 }, { action_type: "discard" }],
    owner: "external-injection-owner",
  },
  {
    nlri: {
      dst_prefix: "2001:db8::10/128", src_prefix: "2001:db8:1::/48", protocol: 17,
      dst_ports: [], fragment: "non_first",
    },
    actions: [{ action_type: "discard" }],
  },
]

function inventory(backend = "rustbgpd", observation_scope: SpeakerRoutesResponse["observation_scope"] = "retained_local_flow_spec_intent"): SpeakerRoutesResponse {
  return { backend, observation_scope, routes }
}

describe("local FlowSpec inventory", () => {
  it.each([
    ["rustbgpd", "retained_local_flow_spec_intent", "Retained local FlowSpec intent"],
    ["gobgp", "accepted_local_flow_spec_rib", "Accepted local FlowSpec RIB"],
    ["custom", "adapter_local_flow_spec", "Adapter-local FlowSpec"],
  ] as const)("shows %s observations with complete matches and all actions", async (backend, scope, label) => {
    controller.route("GET", "/v1/speaker/routes", () => json(inventory(backend, scope)))
    renderApp(<LocalFlowSpecInventory />, { withoutAuth: true })

    const table = await screen.findByRole("table", { name: "Observed local FlowSpec routes" })
    expect(screen.getByText(backend)).toBeInTheDocument()
    expect(screen.getByText(label)).toBeInTheDocument()
    expect(screen.getByText("2 local routes")).toBeInTheDocument()
    const rows = within(table).getAllByRole("row").slice(1)
    expect(rows[0]).toHaveTextContent("203.0.113.10/32")
    expect(rows[0]).toHaveTextContent("UDP from 198.51.100.0/24 src 123, 389 dst 53, 443 length 468–1500 B")
    expect(within(rows[0]).getByText("police 125,000 bps")).toBeInTheDocument()
    expect(within(rows[0]).getByText("discard")).toBeInTheDocument()
    expect(within(rows[0]).getByText("external-injection-owner")).toBeInTheDocument()
    expect(rows[1]).toHaveTextContent("2001:db8::10/128")
    expect(rows[1]).toHaveTextContent("UDP from 2001:db8:1::/48 non-first fragments")
    expect(within(rows[1]).getByText("No injection owner")).toBeInTheDocument()
    const details = rows[0].querySelector("details")
    expect(details?.querySelector("pre")?.textContent).toBe(JSON.stringify(routes[0], null, 2))
    expect(details?.querySelector("summary")).toHaveTextContent("Full rule for 203.0.113.10/32")
    expect(screen.getByText(/does not prove export, router receipt or enforcement/)).toBeInTheDocument()
    expect(screen.getByText(/Excludes blackholes/)).toBeInTheDocument()
    expect(screen.getByText(/does not establish this controller's ownership or a lease deadline/)).toBeInTheDocument()
    expect(controller.requests.map(({ method, path }) => `${method} ${path}`)).toEqual(["GET /v1/speaker/routes"])
    expect(screen.queryByRole("button", { name: /withdraw/i })).not.toBeInTheDocument()
  })

  it("shows initial loading without an empty observation", async () => {
    const pending = deferred<Response>()
    controller.route("GET", "/v1/speaker/routes", () => pending.promise)
    renderApp(<LocalFlowSpecInventory />, { withoutAuth: true })
    expect(screen.getByRole("status", { name: "Loading local FlowSpec routes" })).toBeInTheDocument()
    expect(screen.queryByText("No local FlowSpec routes observed")).not.toBeInTheDocument()
    await act(async () => { pending.resolve(json({ ...inventory(), routes: [] })) })
    expect(await screen.findByText("No local FlowSpec routes observed")).toBeInTheDocument()
    expect(screen.getByText("0 local routes")).toBeInTheDocument()
    expect(screen.getByText(/complete empty FlowSpec inventory/)).toBeInTheDocument()
  })

  it("does not infer ownership or a lease from an empty injection owner", async () => {
    controller.route("GET", "/v1/speaker/routes", () => json({ ...inventory(), routes: [{ ...routes[0], owner: "" }] }))
    renderApp(<LocalFlowSpecInventory />, { withoutAuth: true })
    expect(await screen.findByRole("table")).toHaveTextContent("No injection owner")
    expect(screen.getByText("1 local route")).toBeInTheDocument()
    expect(screen.queryByText("external-injection-owner")).not.toBeInTheDocument()
  })

  it.each([
    [501, "Local FlowSpec observation unsupported"],
    [502, "Unable to observe local FlowSpec routes"],
  ])("keeps HTTP %s distinct from an empty inventory and retries", async (status, title) => {
    let recovered = false
    controller.route("GET", "/v1/speaker/routes", () => recovered ? json(inventory()) : failure(status))
    renderApp(<LocalFlowSpecInventory />, { withoutAuth: true })
    expect(await screen.findByRole("alert")).toHaveTextContent(title)
    expect(screen.getByRole("alert")).toHaveTextContent("Route state is unknown")
    expect(screen.queryByText("No local FlowSpec routes observed")).not.toBeInTheDocument()
    expect(screen.queryByText("0 local routes")).not.toBeInTheDocument()
    expect(screen.queryByRole("table")).not.toBeInTheDocument()
    recovered = true
    fireEvent.click(screen.getByRole("button", { name: "Retry speaker observation" }))
    expect(await screen.findByRole("table")).toBeInTheDocument()
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
    expect(controller.calls("GET", "/v1/speaker/routes")).toHaveLength(2)
  })

  it("hides a previous successful snapshot when its refresh fails and recovers on retry", async () => {
    let failed = false
    controller.route("GET", "/v1/speaker/routes", () => failed ? failure(502) : json(inventory()))
    renderApp(<LocalFlowSpecInventory />, { withoutAuth: true })
    await screen.findByRole("table")
    failed = true
    fireEvent.click(screen.getByRole("button", { name: "Refresh routes" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("rules may still be present")
    expect(screen.queryByRole("table")).not.toBeInTheDocument()
    expect(screen.queryByText("2 local routes")).not.toBeInTheDocument()
    expect(screen.queryByText("Retained local FlowSpec intent")).not.toBeInTheDocument()
    failed = false
    fireEvent.click(screen.getByRole("button", { name: "Retry speaker observation" }))
    expect(await screen.findByRole("table")).toBeInTheDocument()
    expect(controller.calls("GET", "/v1/speaker/routes")).toHaveLength(3)
  })

  it("keeps an opened inspection attached to its rule when a refresh reorders routes", async () => {
    let reversed = false
    controller.route("GET", "/v1/speaker/routes", () => json({ ...inventory(), routes: reversed ? [...routes].reverse() : routes }))
    renderApp(<LocalFlowSpecInventory />, { withoutAuth: true })
    const table = await screen.findByRole("table")
    const summary = screen.getByText("Full rule for 203.0.113.10/32")
    fireEvent.click(summary)
    expect(summary.closest("details")).toHaveAttribute("open")
    reversed = true
    fireEvent.click(screen.getByRole("button", { name: "Refresh routes" }))
    await waitFor(() => expect(within(table).getAllByRole("row")[1]).toHaveTextContent("2001:db8::10/128"))
    expect(screen.getByText("Full rule for 203.0.113.10/32").closest("details")).toHaveAttribute("open")
    expect(screen.getByText("Full rule for 2001:db8::10/128").closest("details")).not.toHaveAttribute("open")
  })

  it("keeps customer inventory usable for a viewer when speaker observation fails", async () => {
    signIn(controller, "credentials", operatorResponse("viewer"))
    controller.route("GET", "/v1/speaker/routes", () => failure(502))
    controller.route("GET", "/v1/config/inventory", () => json({
      customers: [{ customer_id: "customer-a", name: "Customer A", policy_profile: "standard", prefixes: ["203.0.113.0/24"], services: [] }],
      total_customers: 1, total_services: 0, total_assets: 0, loaded_at: "2026-10-23T03:00:00Z",
    }))
    renderApp(<InventoryPage />, { url: "/inventory" })
    expect(await screen.findByRole("alert")).toHaveTextContent("Unable to observe local FlowSpec routes")
    expect(await screen.findByRole("button", { name: "Customer A" })).toBeInTheDocument()
    expect(screen.getByText("1 customers · 0 services · 0 IPs")).toBeInTheDocument()
    fireEvent.change(screen.getByRole("textbox", { name: "Search inventory" }), { target: { value: "does-not-exist" } })
    expect(screen.getByText("No matches found")).toBeInTheDocument()
    await waitFor(() => expect(controller.calls("GET", "/v1/speaker/routes")).toHaveLength(1))
    expect(controller.requests.every(({ method }) => method === "GET")).toBe(true)
  })

  it("keeps speaker observation usable when customer inventory fails", async () => {
    controller.route("GET", "/v1/speaker/routes", () => json(inventory()))
    controller.route("GET", "/v1/config/inventory", () => failure(500))
    renderApp(<InventoryPage />, { url: "/inventory", withoutAuth: true })
    expect(await screen.findByRole("table", { name: "Observed local FlowSpec routes" })).toBeInTheDocument()
    expect(await screen.findByRole("alert")).toHaveTextContent("Unable to load inventory")
    expect(screen.getByText("2 local routes")).toBeInTheDocument()
  })
})
