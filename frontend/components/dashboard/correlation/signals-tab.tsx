"use client"

import { formatConfidence } from "@/lib/confidence"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { useSignalSources, useSignalGroups } from "@/hooks/use-api"
import { Radio, AlertCircle, Layers } from "lucide-react"
import Link from "next/link"

function SourceStatusCards() {
  const { data: sources, error, isLoading } = useSignalSources()

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {[1, 2, 3].map((i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-4 w-24 mb-2" />
              <Skeleton className="h-3 w-32 mb-1" />
              <Skeleton className="h-3 w-20" />
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-4 flex items-center gap-2 text-destructive">
          <AlertCircle className="h-4 w-4" />
          <span className="text-sm font-mono">Failed to load signal sources</span>
        </CardContent>
      </Card>
    )
  }

  if (!sources || sources.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-center">
          <Radio className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm font-mono text-muted-foreground">No signal sources configured</p>
          <p className="text-xs text-muted-foreground mt-1">
            Configure sources in the Config tab to start receiving signals
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
      {sources.map((source) => (
        <Card key={source.name}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span
                  className={`h-2 w-2 rounded-full shrink-0 ${
                    source.healthy ? "bg-green-500" : "bg-muted-foreground"
                  }`}
                />
                <span className="text-sm font-mono font-medium">{source.name}</span>
              </div>
              <Badge variant="outline" className="text-[10px] font-mono">
                {source.type}
              </Badge>
            </div>
            <div className="space-y-1 text-xs font-mono text-muted-foreground">
              <div className="flex justify-between">
                <span>Last seen</span>
                <span className="text-foreground">
                  {source.last_seen
                    ? formatRelativeTime(source.last_seen)
                    : "Never"}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Events</span>
                <span className="text-foreground">{source.event_count}</span>
              </div>
              <div className="flex justify-between">
                <span>Weight</span>
                <span className="text-foreground">{source.weight.toFixed(1)}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function SourceWeightVisualization() {
  const { data: sources } = useSignalSources()

  if (!sources || sources.length === 0) return null

  const totalWeight = sources.reduce((sum, s) => sum + s.weight, 0)

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
          Source Weights
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-4">
        <div className="flex gap-1 h-6 rounded-md overflow-hidden">
          {sources.map((source) => {
            const pct = totalWeight > 0 ? (source.weight / totalWeight) * 100 : 0
            return (
              <div
                key={source.name}
                className="bg-primary/80 hover:bg-primary transition-colors relative group"
                style={{ width: `${pct}%`, minWidth: pct > 0 ? "24px" : "0" }}
                title={`${source.name}: ${source.weight.toFixed(1)} (${pct.toFixed(0)}%)`}
              >
                <span className="absolute inset-0 flex items-center justify-center text-[9px] font-mono text-primary-foreground opacity-0 group-hover:opacity-100 transition-opacity truncate px-1">
                  {source.name}
                </span>
              </div>
            )
          })}
        </div>
        <div className="flex flex-wrap gap-3 mt-2">
          {sources.map((source) => (
            <div key={source.name} className="flex items-center gap-1.5 text-[10px] font-mono text-muted-foreground">
              <span className="h-2 w-2 bg-primary/80 rounded-sm" />
              <span>{source.name}</span>
              <span className="text-foreground">{source.weight.toFixed(1)}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

function RecentSignalsTable() {
  const { data: groupsResp, error, isLoading } = useSignalGroups({ limit: 20 })

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4">
          <Skeleton className="h-4 w-32 mb-4" />
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className="h-8 w-full mb-2" />
          ))}
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-4 flex items-center gap-2 text-destructive">
          <AlertCircle className="h-4 w-4" />
          <span className="text-sm font-mono">Failed to load recent signals</span>
        </CardContent>
      </Card>
    )
  }

  const groups = groupsResp?.groups ?? []

  if (groups.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-center">
          <Layers className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm font-mono text-muted-foreground">No recent signals</p>
          <p className="text-xs text-muted-foreground mt-1">
            Signals will appear here when events are correlated
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
          Recent Signal Groups
        </CardTitle>
      </CardHeader>
      <CardContent className="pb-0">
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="pb-2 pr-3 font-medium">Status</th>
                <th className="pb-2 pr-3 font-medium">Victim IP</th>
                <th className="pb-2 pr-3 font-medium">Vector</th>
                <th className="pb-2 pr-3 font-medium text-right">Confidence</th>
                <th className="pb-2 pr-3 font-medium text-right">Sources</th>
                <th className="pb-2 font-medium text-right">Created</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((group) => (
                <tr
                  key={group.group_id}
                  className="border-b border-border/50 last:border-0 hover:bg-muted/50 transition-colors cursor-pointer"
                >
                  <td className="py-2.5 pr-3">
                    <SignalGroupStatusBadge status={group.status} corroborated={group.corroboration_met} />
                  </td>
                  <td className="py-2.5 pr-3">
                    <Link
                      href={`/correlation/groups/${group.group_id}`}
                      className="text-foreground hover:text-primary transition-colors"
                    >
                      {group.victim_ip}
                    </Link>
                  </td>
                  <td className="py-2.5 pr-3 text-muted-foreground">{group.vector.replace(/_/g, " ")}</td>
                  <td className="py-2.5 pr-3 text-right tabular-nums">
                    {formatConfidence(group.derived_confidence)}
                  </td>
                  <td className="py-2.5 pr-3 text-right tabular-nums">{group.source_count}</td>
                  <td className="py-2.5 text-right text-muted-foreground">
                    {formatRelativeTime(group.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}

export function SignalGroupStatusBadge({ status, corroborated }: { status: string; corroborated?: boolean }) {
  if (status === "resolved") {
    return (
      <Badge variant="default" className="text-[10px] bg-green-600 hover:bg-green-600">
        Resolved
      </Badge>
    )
  }
  if (status === "expired") {
    return (
      <Badge variant="secondary" className="text-[10px]">
        Expired
      </Badge>
    )
  }
  // open
  return (
    <Badge variant={corroborated ? "default" : "outline"} className="text-[10px]">
      {corroborated ? "Corroborated" : "Open"}
    </Badge>
  )
}

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const minutes = Math.floor(diff / 60000)
  if (minutes < 1) return "Just now"
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

// Re-export for use in groups tab
export { formatRelativeTime }

export function SignalsTab() {
  return (
    <div className="space-y-4">
      <SourceStatusCards />
      <SourceWeightVisualization />
      <RecentSignalsTable />
    </div>
  )
}
