"use client"

import { useState, useCallback } from "react"
import { useSearchParams, useRouter } from "next/navigation"
import Link from "next/link"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useSignalGroupsPaginated } from "@/hooks/use-api"
import { Layers, AlertCircle, Loader2, XCircle } from "lucide-react"
import { SignalGroupStatusBadge, formatRelativeTime } from "./signals-tab"
import { formatConfidence, isConfidence } from "@/lib/confidence"

const STATUS_OPTIONS = [
  { value: "all", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "resolved", label: "Resolved" },
  { value: "expired", label: "Expired" },
]

const VECTOR_OPTIONS = [
  { value: "all", label: "All vectors" },
  { value: "udp_flood", label: "UDP Flood" },
  { value: "syn_flood", label: "SYN Flood" },
  { value: "ntp_amplification", label: "NTP Amplification" },
  { value: "dns_amplification", label: "DNS Amplification" },
  { value: "memcached_amplification", label: "Memcached Amplification" },
  { value: "ssdp_amplification", label: "SSDP Amplification" },
  { value: "icmp_flood", label: "ICMP Flood" },
]

export function GroupsTab() {
  const searchParams = useSearchParams()
  const router = useRouter()

  // Read filters from URL params with sensible defaults
  const [status, setStatus] = useState(searchParams.get("status") || "open")
  const [vector, setVector] = useState(searchParams.get("vector") || "all")

  // Sync URL params when filters change
  const updateUrlParams = useCallback(
    (newStatus: string, newVector: string) => {
      const params = new URLSearchParams()
      if (newStatus !== "open") params.set("status", newStatus)
      if (newVector !== "all") params.set("vector", newVector)
      const query = params.toString()
      router.replace(`/correlation${query ? `?${query}` : ""}`, { scroll: false })
    },
    [router],
  )

  const handleStatusChange = (val: string) => {
    setStatus(val)
    updateUrlParams(val, vector)
  }

  const handleVectorChange = (val: string) => {
    setVector(val)
    updateUrlParams(status, val)
  }

  const clearFilters = () => {
    setStatus("open")
    setVector("all")
    updateUrlParams("open", "all")
  }

  const hasActiveFilters = status !== "open" || vector !== "all"

  const filterParams = {
    status: status === "all" ? undefined : status,
    vector: vector === "all" ? undefined : vector,
    limit: 25,
  }

  const { data, error, isLoading, isValidating, size, setSize } = useSignalGroupsPaginated(filterParams)

  const groups = data ? data.flatMap((page) => page.groups) : []
  const hasMore = data ? data[data.length - 1]?.has_more ?? false : false
  const isLoadingMore = isValidating && size > 1

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Select value={status} onValueChange={handleStatusChange}>
          <SelectTrigger className="w-[140px] h-8 text-xs font-mono">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATUS_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value} className="text-xs font-mono">
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={vector} onValueChange={handleVectorChange}>
          <SelectTrigger className="w-[180px] h-8 text-xs font-mono">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {VECTOR_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value} className="text-xs font-mono">
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={clearFilters}
            className="h-8 text-xs font-mono text-muted-foreground hover:text-foreground"
          >
            <XCircle className="h-3 w-3 mr-1" />
            Clear filters
          </Button>
        )}
      </div>

      {/* Content */}
      {isLoading ? (
        <Card>
          <CardContent className="p-4">
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} className="h-10 w-full mb-2" />
            ))}
          </CardContent>
        </Card>
      ) : error ? (
        <Card>
          <CardContent className="p-4 flex items-center gap-2 text-destructive">
            <AlertCircle className="h-4 w-4" />
            <span className="text-sm font-mono">Failed to load signal groups</span>
          </CardContent>
        </Card>
      ) : groups.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center">
            <Layers className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
            <p className="text-sm font-mono text-muted-foreground">No signal groups found</p>
            <p className="text-xs text-muted-foreground mt-1">
              {hasActiveFilters
                ? "Try adjusting your filters"
                : "Signal groups will appear here when events are correlated"}
            </p>
            {hasActiveFilters && (
              <Button
                variant="outline"
                size="sm"
                onClick={clearFilters}
                className="mt-3 text-xs font-mono"
              >
                Clear filters
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-mono">
                <thead>
                  <tr className="border-b border-border text-left text-muted-foreground">
                    <th className="p-3 font-medium">Status</th>
                    <th className="p-3 font-medium">Victim IP</th>
                    <th className="p-3 font-medium">Vector</th>
                    <th className="p-3 font-medium text-right">Confidence</th>
                    <th className="p-3 font-medium text-right">Sources</th>
                    <th className="p-3 font-medium text-right">Created</th>
                    <th className="p-3 font-medium text-right">Window</th>
                  </tr>
                </thead>
                <tbody>
                  {groups.map((group) => (
                    <tr
                      key={group.group_id}
                      className="border-b border-border/50 last:border-0 hover:bg-muted/50 transition-colors"
                    >
                      <td className="p-3">
                        <SignalGroupStatusBadge status={group.status} corroborated={group.corroboration_met} />
                      </td>
                      <td className="p-3">
                        <Link
                          href={`/correlation/groups/${group.group_id}`}
                          className="text-foreground hover:text-primary transition-colors"
                        >
                          {group.victim_ip}
                        </Link>
                      </td>
                      <td className="p-3 text-muted-foreground">{group.vector.replace(/_/g, " ")}</td>
                      <td className="p-3 text-right tabular-nums">
                        <ConfidenceDisplay confidence={group.derived_confidence} />
                      </td>
                      <td className="p-3 text-right tabular-nums">{group.source_count}</td>
                      <td className="p-3 text-right text-muted-foreground">
                        {formatRelativeTime(group.created_at)}
                      </td>
                      <td className="p-3 text-right text-muted-foreground">
                        {group.status === "open"
                          ? formatRelativeTime(group.window_expires_at)
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {hasMore && (
              <div className="p-3 border-t border-border">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSize(size + 1)}
                  disabled={isLoadingMore}
                  className="w-full text-xs font-mono"
                >
                  {isLoadingMore ? (
                    <>
                      <Loader2 className="h-3 w-3 mr-1.5 animate-spin" />
                      Loading...
                    </>
                  ) : (
                    "Load More"
                  )}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function ConfidenceDisplay({ confidence }: { confidence: number }) {
  let colorClass = "text-muted-foreground"
  if (isConfidence(confidence)) {
    if (confidence >= 0.8) colorClass = "text-green-600 dark:text-green-400"
    else if (confidence >= 0.5) colorClass = "text-yellow-600 dark:text-yellow-400"
    else colorClass = "text-red-600 dark:text-red-400"
  }

  return <span className={colorClass}>{formatConfidence(confidence)}</span>
}
