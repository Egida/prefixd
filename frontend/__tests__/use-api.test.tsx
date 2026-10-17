import React, { type ReactNode } from "react"
import { act, renderHook, waitFor } from "@testing-library/react"
import { SWRConfig } from "swr"
import { beforeEach, describe, expect, it, vi } from "vitest"
import * as api from "@/lib/api"
import { useEvents, useMitigation, useMitigations, useSignalGroupDetail, useSignalGroupsPaginated } from "@/hooks/use-api"

vi.mock("@/lib/api", () => ({
  getMitigations: vi.fn(), getEvents: vi.fn(), getMitigation: vi.fn(),
  getSignalGroupDetail: vi.fn(), getSignalGroups: vi.fn(),
}))

function wrapper({ children }: { children: ReactNode }) {
  return <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>{children}</SWRConfig>
}

beforeEach(() => vi.clearAllMocks())

describe("real API hooks", () => {
  it("forwards mitigation filters to the API", async () => {
    vi.mocked(api.getMitigations).mockResolvedValue({ mitigations: [], count: 0, next_cursor: null, has_more: false })
    const filters = { status: ["active"], customer_id: "customer-a", limit: 10 }
    renderHook(() => useMitigations(filters), { wrapper })
    await waitFor(() => expect(api.getMitigations).toHaveBeenCalledWith(filters))
  })

  it("forwards event filters to the API", async () => {
    vi.mocked(api.getEvents).mockResolvedValue({ events: [], count: 0, next_cursor: null, has_more: false })
    const filters = { limit: 10, cursor: "event-cursor" }
    renderHook(() => useEvents(filters), { wrapper })
    await waitFor(() => expect(api.getEvents).toHaveBeenCalledWith(filters))
  })

  it("does not fetch detail records without an identifier", async () => {
    const { result } = renderHook(() => ({ mitigation: useMitigation(null), group: useSignalGroupDetail(null) }), { wrapper })
    await act(async () => {})
    expect(result.current.mitigation.isLoading).toBe(false)
    expect(result.current.group.isLoading).toBe(false)
    expect(api.getMitigation).not.toHaveBeenCalled()
    expect(api.getSignalGroupDetail).not.toHaveBeenCalled()
  })

  it("carries the returned cursor into the next signal-group request", async () => {
    vi.mocked(api.getSignalGroups).mockImplementation(async (params) => ({
      groups: [], count: 0, next_cursor: params?.cursor ? null : "next-page", has_more: !params?.cursor,
    }))
    const { result } = renderHook(() => useSignalGroupsPaginated({ status: "open", limit: 2 }), { wrapper })
    await waitFor(() => expect(result.current.data?.length).toBe(1))
    await act(async () => { await result.current.setSize(2) })
    await waitFor(() => expect(result.current.data?.length).toBe(2))
    expect(api.getSignalGroups).toHaveBeenCalledWith({ status: "open", limit: 2, cursor: "next-page" })
    await act(async () => { await result.current.setSize(3) })
    expect(result.current.data?.length).toBe(2)
  })
})
